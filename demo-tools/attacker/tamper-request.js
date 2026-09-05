#!/usr/bin/env node
// =============================================================================
//  tamper-request.js  —  SIMULATED SIGNED-REQUEST TAMPER/REPLAY, DEMO USE ONLY
// =============================================================================
//
//  Scene 3. The attacker sniffed a COMPLETE, correctly-signed request from the
//  victim (cookie + X-KAAVAL-Proof header + body). Two ways it tries to abuse it:
//
//    (default)    keep the victim's real signature, rewrite the body (amount)
//                 -> gateway recomputes body_hash, it no longer matches the
//                    signed one -> HTTP 401, reason body_hash_mismatch.
//    --verbatim   resend the captured request completely unchanged
//                 -> the single-use nonce was already spent -> HTTP 401,
//                    reason nonce_reused.
//
//  Neither works, because the proof is bound to THIS body and THIS nonce and
//  cannot be re-forged without the non-exportable session private key — which
//  never left the victim's browser, so the proxy never saw it.
//
//  A captured envelope is a JSON file (default ./.captured-envelope.json):
//    {
//      "base_url": "http://localhost:8000",
//      "path": "/api/transfer",
//      "mode": "protected",
//      "cookie": "<kaaval_session value>",
//      "proof":  "<X-KAAVAL-Proof header value, base64url>",
//      "body":   { "to_account": "acct-demo-1", "amount": 250 }
//    }
//  Obtain one from the victim's real signed request (e.g. Chrome DevTools ->
//  Network -> the /api/transfer call: copy the Cookie, the X-KAAVAL-Proof
//  header, and the request body into the file above). The authoritative,
//  fully-automated version of this scene is backend/attacker_console/replay.py.
//
//  Usage:
//    node tamper-request.js [--envelope FILE] [--field amount] [--value 999999]
//    node tamper-request.js --verbatim [--envelope FILE]

"use strict";

const fs = require("fs");
const path = require("path");

const DEFAULT_ENVELOPE = path.join(__dirname, ".captured-envelope.json");
const COOKIE_NAME = "kaaval_session";

function parseArgs(argv) {
  const out = { verbatim: false, field: "amount", value: "999999" };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--verbatim") out.verbatim = true;
    else if (a === "--envelope") out.envelope = argv[++i];
    else if (a === "--field") out.field = argv[++i];
    else if (a === "--value") out.value = argv[++i];
  }
  return out;
}

function loadEnvelope(file) {
  if (!fs.existsSync(file)) {
    console.error(`[tamper-request] no captured envelope at ${file}`);
    console.error(`  Create it from the victim's real signed /api/transfer request`);
    console.error(`  (see the header comment in this file for the exact JSON shape),`);
    console.error(`  or run the full scene via: python -m backend.attacker_console.replay`);
    process.exit(1);
  }
  let env;
  try {
    env = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (err) {
    console.error(`[tamper-request] ${file} is not valid JSON: ${err.message}`);
    process.exit(1);
  }
  for (const key of ["cookie", "proof", "body"]) {
    if (env[key] === undefined) {
      console.error(`[tamper-request] captured envelope is missing "${key}".`);
      process.exit(1);
    }
  }
  env.base_url = (env.base_url || "http://localhost:8000").replace(/\/$/, "");
  env.path = env.path || "/api/transfer";
  env.mode = env.mode || "protected";
  env.origin = env.origin || originFromProof(env.proof);
  return env;
}

// The gateway's check 3 compares the envelope's asserted `origin` against the
// request's actual Origin header, and that check runs BEFORE the body-hash
// (check 4) and nonce (check 5) checks. A replay that omits the Origin header
// therefore fails as `request_mismatch` at check 3 and never reaches the
// body_hash_mismatch / nonce_reused this tool exists to demonstrate. The
// victim's browser signs with, and sends, its own origin, so a faithful
// replay must reproduce it — read straight out of the captured proof so it
// always matches what was signed.
function originFromProof(proof) {
  try {
    const decoded = JSON.parse(Buffer.from(proof, "base64").toString("utf8"));
    if (typeof decoded.origin === "string" && decoded.origin) return decoded.origin;
  } catch {
    // fall through to the default
  }
  return "http://localhost:3000";
}

function coerce(original, value) {
  return typeof original === "number" && value !== "" && !Number.isNaN(Number(value))
    ? Number(value)
    : value;
}

async function post(env, bodyObj, label) {
  const url = `${env.base_url}${env.path}?mode=${env.mode}`;
  console.log(`[tamper-request] ${label}`);
  console.log(`  POST ${url}`);
  let res, text;
  try {
    res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-KAAVAL-Proof": env.proof,
        // Reproduce the origin the envelope was signed against, exactly as the
        // victim's browser would send it, so the request reaches the body-hash
        // and nonce checks instead of failing earlier at the origin check.
        Origin: env.origin,
        Cookie: `${COOKIE_NAME}=${env.cookie}`,
      },
      body: JSON.stringify(bodyObj),
    });
    text = await res.text();
  } catch (err) {
    console.error(`  request failed: ${err.message}`);
    console.error(`  Is the core stack running? base_url=${env.base_url}`);
    process.exit(1);
  }
  console.log(`  HTTP ${res.status}  ${text}`);
  return { status: res.status, text };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const env = loadEnvelope(args.envelope || DEFAULT_ENVELOPE);

  if (args.verbatim) {
    const { text } = await post(env, env.body, "replaying the captured request VERBATIM");
    console.log(
      text.includes("nonce_reused")
        ? "  -> BLOCKED as expected: nonce_reused (the single-use nonce was already spent)."
        : "  -> check the reason above; expected nonce_reused.",
    );
    return;
  }

  const tampered = { ...env.body };
  const before = tampered[args.field];
  tampered[args.field] = coerce(before, args.value);
  console.log(
    `[tamper-request] rewriting body.${args.field}: ${JSON.stringify(before)} -> ${JSON.stringify(tampered[args.field])} (keeping the victim's original signature)`,
  );
  const { text } = await post(env, tampered, "reposting the TAMPERED body with the stolen proof");
  console.log(
    text.includes("body_hash_mismatch")
      ? "  -> BLOCKED as expected: body_hash_mismatch (signature is bound to the original body)."
      : "  -> check the reason above; expected body_hash_mismatch.",
  );
}

main();
