#!/usr/bin/env node
// =============================================================================
//  hacker-console.js  —  ATTACKER WEB CONSOLE (SIMULATED AiTM, DEMO USE ONLY)
// =============================================================================
//
//  The browser-driven equivalent of replay-cookie.js + tamper-request.js, for
//  the two-laptop LAN demo:
//
//    Laptop A (victim)   -> browses https://kaaval.demo/  (the SOC dashboard)
//                           and https://kaaval.demo/demo  (registers a passkey,
//                           logs in, makes a PulseLock-signed transfer).
//    Laptop B (attacker) -> runs the TLS proxy (attacker-proxy.js), which skims
//                           the victim's session cookie and signed request off
//                           the wire into capture files, AND runs THIS console,
//                           which the attacker drives from a browser to try to
//                           abuse what was skimmed.
//
//  WHY A SERVER AND NOT JUST A STATIC PAGE:
//    The whole attack is "send the victim's cookie / signed proof from somewhere
//    that isn't the victim's browser." A browser `fetch` cannot set the `Cookie`
//    or `Origin` headers (both are forbidden headers), and a cross-origin call
//    to the backend would be blocked by CORS anyway. So the static page is only
//    the UI; every real attack request is made HERE, server-side, with full
//    header control — exactly as the CLI scripts do. The page calls this
//    console's own same-origin API, and this console hits the backend.
//
//  Every attack request below hits the REAL backend at BACKEND_TARGET, so the
//  resulting SecurityEvent (proof_absent, body_hash_mismatch, nonce_reused, or
//  the baseline "allowed") flows over SSE to the victim's dashboard on Laptop A
//  and lights up its live feed. That is the point of the demo.
//
//  Built on Node's built-in http only — no npm install. Requires Node 18+ for
//  the global `fetch` (same requirement the sibling CLI scripts already have).
//
//  Env (all optional):
//    HACKER_PORT     port to serve the console UI on   (default 8080)
//    BACKEND_TARGET  gateway the attacks hit           (default http://localhost:8000)
//    CAPTURE_DIR     dir holding the capture files      (default this file's dir)

"use strict";

const http = require("http");
const fs = require("fs");
const path = require("path");

const HACKER_PORT = parseInt(process.env.HACKER_PORT || "8080", 10);
const BACKEND_TARGET = (process.env.BACKEND_TARGET || "http://localhost:8000").replace(/\/$/, "");
const CAPTURE_DIR = process.env.CAPTURE_DIR || __dirname;

const COOKIE_FILE = path.join(CAPTURE_DIR, ".captured-cookie");
const ENVELOPE_FILE = path.join(CAPTURE_DIR, ".captured-envelope.json");
const FEED_FILE = path.join(CAPTURE_DIR, ".captures.jsonl");
const PAGE_FILE = path.join(__dirname, "hacker-page.html");

const COOKIE_NAME = "kaaval_session";
const TRANSFER_PATH = "/api/transfer";

// --- capture readers --------------------------------------------------------

function readCapturedCookie() {
  try {
    const value = fs.readFileSync(COOKIE_FILE, "utf8").trim();
    return value || null;
  } catch {
    return null;
  }
}

function readCapturedEnvelope() {
  try {
    const env = JSON.parse(fs.readFileSync(ENVELOPE_FILE, "utf8"));
    if (env && typeof env === "object" && env.proof && env.body !== undefined) {
      return env;
    }
    return null;
  } catch {
    return null;
  }
}

// The gateway checks the envelope's asserted origin (check 3) BEFORE body_hash
// (check 4) and nonce (check 5). A replay that omits Origin fails early as
// request_mismatch and never reaches the checks these attacks want to trip, so
// reproduce the origin the proof was actually signed against.
function originFromProof(proof) {
  try {
    const decoded = JSON.parse(Buffer.from(proof, "base64").toString("utf8"));
    if (typeof decoded.origin === "string" && decoded.origin) return decoded.origin;
  } catch {
    // fall through
  }
  return "http://localhost:3000";
}

function reasonFromResponseText(text) {
  try {
    const parsed = JSON.parse(text);
    const detail = parsed && parsed.detail;
    if (detail && typeof detail === "object" && typeof detail.reason === "string") {
      return detail.reason;
    }
    if (typeof detail === "string") return detail;
  } catch {
    // not JSON; leave null
  }
  return null;
}

// --- attack executors -------------------------------------------------------

async function replayCookie(mode) {
  const cookie = readCapturedCookie();
  if (!cookie) {
    return {
      ok: false,
      error: "No stolen cookie captured yet. Have the victim log in through the proxy first (Scene 0).",
    };
  }
  const url = `${BACKEND_TARGET}${TRANSFER_PATH}?mode=${mode}`;
  const body = JSON.stringify({ to_account: "acct-attacker", amount: 5000 });
  let res, text;
  try {
    res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Cookie: `${COOKIE_NAME}=${cookie}`,
      },
      body,
    });
    text = await res.text();
  } catch (err) {
    return { ok: false, error: `Request to backend failed: ${err.message} (is start-demo.sh running?)` };
  }
  const reason = reasonFromResponseText(text);
  const succeeded = res.ok;
  let verdict, verdictKind;
  if (mode === "baseline") {
    verdict = succeeded
      ? "TRANSFER WENT THROUGH — the stolen cookie alone is enough. The theft is real."
      : "Unexpected: baseline replay did not succeed; the negative control is broken.";
    verdictKind = succeeded ? "attack-worked" : "warn";
  } else {
    verdict = !succeeded
      ? "BLOCKED — the stolen cookie is worthless under PulseLock (no valid proof)."
      : "Unexpected: protected mode accepted a cookie with no proof.";
    verdictKind = !succeeded ? "defended" : "warn";
  }
  return { ok: true, mode, status: res.status, reason, body: text, verdict, verdictKind };
}

async function postSigned(env, bodyObj) {
  const base = (process.env.BACKEND_TARGET ? BACKEND_TARGET : env.base_url || BACKEND_TARGET).replace(/\/$/, "");
  const mode = env.mode || "protected";
  const url = `${base}${env.path || TRANSFER_PATH}?mode=${mode}`;
  const origin = env.origin || originFromProof(env.proof);
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-KAAVAL-Proof": env.proof,
      Origin: origin,
      Cookie: `${COOKIE_NAME}=${env.cookie || readCapturedCookie() || ""}`,
    },
    body: JSON.stringify(bodyObj),
  });
  const text = await res.text();
  return { status: res.status, text };
}

async function tamperRequest(field, value) {
  const env = readCapturedEnvelope();
  if (!env) {
    return {
      ok: false,
      error: "No signed request captured yet. Have the victim make a PulseLock-protected transfer through the proxy first (Scene 3 setup).",
    };
  }
  const tampered = { ...env.body };
  const before = tampered[field];
  const coerced =
    typeof before === "number" && value !== "" && !Number.isNaN(Number(value))
      ? Number(value)
      : value;
  tampered[field] = coerced;
  let result;
  try {
    result = await postSigned(env, tampered);
  } catch (err) {
    return { ok: false, error: `Request to backend failed: ${err.message}` };
  }
  const reason = reasonFromResponseText(result.text);
  const blocked = reason === "body_hash_mismatch" || (result.status >= 400 && !result.text.includes('"status":"ok"'));
  return {
    ok: true,
    status: result.status,
    reason,
    body: result.text,
    verdict:
      reason === "body_hash_mismatch"
        ? `BLOCKED — body_hash_mismatch. The signature is bound to the victim's original ${field}=${JSON.stringify(before)}; rewriting it to ${JSON.stringify(coerced)} invalidates the proof.`
        : "Check the reason above; expected body_hash_mismatch.",
    verdictKind: reason === "body_hash_mismatch" ? "defended" : "warn",
    changed: { field, before, after: coerced },
  };
}

async function replaySignedVerbatim() {
  const env = readCapturedEnvelope();
  if (!env) {
    return {
      ok: false,
      error: "No signed request captured yet. Have the victim make a PulseLock-protected transfer through the proxy first.",
    };
  }
  let result;
  try {
    result = await postSigned(env, env.body);
  } catch (err) {
    return { ok: false, error: `Request to backend failed: ${err.message}` };
  }
  const reason = reasonFromResponseText(result.text);
  const blocked = reason === "nonce_reused" || (result.status >= 400 && !result.text.includes('"status":"ok"'));
  return {
    ok: true,
    status: result.status,
    reason,
    body: result.text,
    verdict:
      reason === "nonce_reused"
        ? "BLOCKED — nonce_reused. The single-use nonce was already spent by the victim's real request; the proof cannot be replayed."
        : "Check the reason above; expected nonce_reused (a fresh capture is needed if the victim has not sent a new signed request since the last replay).",
    verdictKind: reason === "nonce_reused" ? "defended" : "warn",
  };
}

// --- tiny HTTP plumbing -----------------------------------------------------

function sendJson(res, status, obj) {
  const payload = JSON.stringify(obj);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
  });
  res.end(payload);
}

function readJsonBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      if (chunks.length === 0) return resolve({});
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch {
        resolve({});
      }
    });
    req.on("error", () => resolve({}));
  });
}

function maskCookie(value) {
  if (!value) return null;
  if (value.length <= 12) return `${value.slice(0, 4)}…`;
  return `${value.slice(0, 8)}…${value.slice(-4)} (${value.length} chars)`;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${HACKER_PORT}`);
  const route = url.pathname;

  if (req.method === "GET" && (route === "/" || route === "/index.html")) {
    fs.readFile(PAGE_FILE, (err, data) => {
      if (err) {
        res.writeHead(500, { "Content-Type": "text/plain" });
        res.end(`hacker-page.html not found next to hacker-console.js: ${err.message}`);
        return;
      }
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
      res.end(data);
    });
    return;
  }

  // Live interception feed (Server-Sent Events). Streams every capture the proxy
  // appends to .captures.jsonl to the attacker dashboard as it happens. The proxy
  // and this console are separate processes, so we tail the file by polling its
  // size and emitting any newly-appended lines — robust across platforms and to
  // the proxy truncating the file on its own restart.
  if (req.method === "GET" && route === "/api/capture-stream") {
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-store",
      Connection: "keep-alive",
    });
    res.write(": connected\n\n");

    let offset = 0;
    let carry = "";

    const emitLine = (line) => {
      const trimmed = line.trim();
      if (trimmed) res.write(`data: ${trimmed}\n\n`);
    };

    const pump = () => {
      let size;
      try {
        size = fs.statSync(FEED_FILE).size;
      } catch {
        return; // feed file not created yet; try again next tick
      }
      if (size < offset) {
        // file was truncated (proxy restarted) — start over
        offset = 0;
        carry = "";
      }
      if (size === offset) return;
      let chunk;
      try {
        const fd = fs.openSync(FEED_FILE, "r");
        const buf = Buffer.alloc(size - offset);
        fs.readSync(fd, buf, 0, buf.length, offset);
        fs.closeSync(fd);
        chunk = buf.toString("utf8");
      } catch {
        return;
      }
      offset = size;
      const parts = (carry + chunk).split("\n");
      carry = parts.pop() ?? "";
      for (const line of parts) emitLine(line);
    };

    // Replay whatever is already in the feed, then poll for new lines.
    pump();
    const interval = setInterval(pump, 500);
    const heartbeat = setInterval(() => res.write(": ping\n\n"), 15000);
    const stop = () => {
      clearInterval(interval);
      clearInterval(heartbeat);
    };
    req.on("close", stop);
    res.on("error", stop);
    return;
  }

  if (req.method === "GET" && route === "/api/captures") {
    const cookie = readCapturedCookie();
    const env = readCapturedEnvelope();
    sendJson(res, 200, {
      backend: BACKEND_TARGET,
      cookie: cookie ? { present: true, preview: maskCookie(cookie) } : { present: false },
      envelope: env
        ? {
            present: true,
            path: env.path || TRANSFER_PATH,
            mode: env.mode || "protected",
            body: env.body,
            origin: env.origin || originFromProof(env.proof),
            proofPreview: `${String(env.proof).slice(0, 16)}… (${String(env.proof).length} chars)`,
          }
        : { present: false },
    });
    return;
  }

  if (req.method === "POST" && route === "/api/replay-cookie") {
    const { mode } = await readJsonBody(req);
    const chosen = mode === "protected" ? "protected" : "baseline";
    sendJson(res, 200, await replayCookie(chosen));
    return;
  }

  if (req.method === "POST" && route === "/api/tamper") {
    const { field, value } = await readJsonBody(req);
    sendJson(res, 200, await tamperRequest(field || "amount", value === undefined ? "999999" : String(value)));
    return;
  }

  if (req.method === "POST" && route === "/api/replay-signed") {
    sendJson(res, 200, await replaySignedVerbatim());
    return;
  }

  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("not found");
});

server.listen(HACKER_PORT, () => {
  console.log(`[hacker-console] SIMULATED ATTACKER CONSOLE — DEMO ONLY`);
  console.log(`[hacker-console] UI:       http://localhost:${HACKER_PORT}/`);
  console.log(`[hacker-console] attacks hit backend: ${BACKEND_TARGET}`);
  console.log(`[hacker-console] reading captures from: ${CAPTURE_DIR}`);
  console.log(`[hacker-console] every attempt appears on the victim's dashboard live feed.`);
});

server.on("error", (err) => {
  if (err.code === "EADDRINUSE") {
    console.error(`[hacker-console] FATAL: port ${HACKER_PORT} already in use. Set HACKER_PORT=... to change it.`);
  } else {
    console.error("[hacker-console] FATAL:", err.message);
  }
  process.exit(1);
});
