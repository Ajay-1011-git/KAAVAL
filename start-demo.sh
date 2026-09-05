#!/usr/bin/env bash
# =============================================================================
#  start-demo.sh — one-command KAAVAL two-laptop LAN demo stack (Laptop B)
# =============================================================================
#  KAAVAL_Demo_LAN_Reengineering.md §4. Run from the repo root on the
#  attacker/host laptop. Starts the CORE STACK ONLY (backend -> frontend),
#  waiting for each to be reachable. The TLS attacker proxy is a SEPARATE
#  step: after this is up, run  demo-tools/attacker/run-attacker.sh.
#
#  Differences from the doc's illustrative snippet, all required for THIS repo:
#    * venv lives at repo-root .venv (not backend/venv), and the app runs as
#      `backend.main:app` from the repo root (its imports are absolute
#      `backend.*`), so we do NOT `cd backend`.
#    * backend readiness is polled on /health (a clean 200), not on the
#      never-closing SSE stream /events/stream, which would hang the wait loop.
#    * the frontend is BUILT and run with `next start`, not `next dev`. Dev
#      mode's webpack-HMR client opens a `wss://.../_next/webpack-hmr`
#      WebSocket back through the attacker-proxy's upgrade forwarding; on the
#      two-laptop LAN path that handshake reliably fails
#      ("Connection closed before receiving a handshake response"), and a
#      failed/looping HMR client can leave the page appearing to hydrate while
#      React event handlers never actually attach. Production mode has no HMR
#      client at all, so this failure mode cannot occur. Rebuild after any
#      frontend source change.
#
#  Override any of these before running:
#    PROXY_PORT   TLS port for the proxy   (default 443; needs sudo)
#    BACKEND_PORT FastAPI port             (default 8000)
#    FRONTEND_PORT Next.js port            (default 3000)
#    DEMO_HOST    hostname the victim uses (default kaaval.demo)
#    DEMO_PROXY_PORT  proxy TLS port folded into the demo origin (default 443)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

BACKEND_PORT="${BACKEND_PORT:-8000}"
FRONTEND_PORT="${FRONTEND_PORT:-3000}"

# --- LAN demo identity ------------------------------------------------------
# The victim laptop reaches everything through the attacker's TLS proxy at a
# single origin (https://kaaval.demo). Three things must agree on that origin,
# or the demo half-works — styled but with dead buttons, or a rejected passkey:
#   * the frontend's NEXT_PUBLIC_BACKEND_ORIGIN, baked at BUILD time, is where
#     the demo page's SDK sends its requests. If it stays http://localhost:8000
#     the victim's browser calls a backend that isn't on the victim laptop.
#   * NEXT_PUBLIC_WEBAUTHN_RP_ID is the relying-party id the ceremony uses.
#   * the backend's WEBAUTHN_RP_ID / WEBAUTHN_RP_ORIGIN are what it verifies
#     the assertion against, and must match the page's real origin exactly.
# These are exported here rather than written into anyone's .env: the backend's
# load_dotenv runs override=False so an exported var wins over .env, and Next
# reads NEXT_PUBLIC_* from the environment at build time ahead of .env.local —
# both verified. So this sets the demo up correctly without mutating the
# single-machine dev config in those files. Override any of them explicitly.
DEMO_HOST="${DEMO_HOST:-kaaval.demo}"
DEMO_PROXY_PORT="${DEMO_PROXY_PORT:-443}"
if [ "$DEMO_PROXY_PORT" = "443" ]; then
  DEMO_ORIGIN="https://${DEMO_HOST}"
else
  DEMO_ORIGIN="https://${DEMO_HOST}:${DEMO_PROXY_PORT}"
fi

export WEBAUTHN_RP_ID="${WEBAUTHN_RP_ID:-$DEMO_HOST}"
export WEBAUTHN_RP_ORIGIN="${WEBAUTHN_RP_ORIGIN:-$DEMO_ORIGIN}"
export NEXT_PUBLIC_BACKEND_ORIGIN="${NEXT_PUBLIC_BACKEND_ORIGIN:-$DEMO_ORIGIN}"
export NEXT_PUBLIC_WEBAUTHN_RP_ID="${NEXT_PUBLIC_WEBAUTHN_RP_ID:-$DEMO_HOST}"

echo "Starting KAAVAL demo stack (repo: $REPO_ROOT)..."
echo "  demo origin: $DEMO_ORIGIN  (rp id: $DEMO_HOST)"
echo "  the frontend is built against this origin — rebuilds on every run."

# Prefer a venv interpreter directly so we don't depend on the caller having
# activated it. The README creates .venv at the repo root; this repo has also
# historically carried backend/.venv, so accept either rather than failing on
# a layout that is genuinely present.
PY=""
for candidate in "$REPO_ROOT/.venv/bin/python" "$REPO_ROOT/backend/.venv/bin/python"; do
  if [ -x "$candidate" ]; then PY="$candidate"; break; fi
done
if [ -z "$PY" ]; then
  echo "ERROR: no virtualenv found at $REPO_ROOT/.venv or $REPO_ROOT/backend/.venv." >&2
  echo "  Create one (README §2) first." >&2
  exit 1
fi

# A previous stack (or a second copy of this script) left something bound to
# one of our ports is the single most common real-world failure here — uvicorn
# or next would otherwise die deep in a stack trace with an opaque EADDRINUSE.
# Reclaim the ports outright rather than making the operator go run
# stop-demo.sh by hand first: kill whatever is listening, wait for it to let
# go, then proceed. Same logic as stop-demo.sh, inlined so this script is
# self-sufficient.
port_busy() { lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; }
free_port() {
  local port="$1" label="$2"
  port_busy "$port" || return 0
  local pids
  pids="$(lsof -ti tcp:"$port" 2>/dev/null || true)"
  echo "Port $port ($label) is in use by PID(s) ${pids:-?} — stopping..."
  [ -n "$pids" ] && kill $pids 2>/dev/null || true
  for _ in $(seq 1 20); do
    port_busy "$port" || return 0
    sleep 0.25
  done
  # Still there after ~5s of graceful shutdown — force it.
  pids="$(lsof -ti tcp:"$port" 2>/dev/null || true)"
  [ -n "$pids" ] && kill -9 $pids 2>/dev/null || true
  sleep 0.25
}
free_port "$BACKEND_PORT" "backend"
free_port "$FRONTEND_PORT" "frontend"

pids=()
cleanup() {
  echo ""
  echo "Stopping KAAVAL demo stack..."
  for pid in "${pids[@]:-}"; do
    [ -n "${pid:-}" ] && kill "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT INT TERM

# 1. Backend (FastAPI: gateway, Radar, Guardian, Chronicle, SSE)
"$PY" -m uvicorn backend.main:app --port "$BACKEND_PORT" --reload &
pids+=($!)

# 2. Frontend (Next.js dashboard + /demo) — production build+start (see the
#    HMR/WebSocket note above). Build first so `next start` finds .next/.
#    NEXT_PUBLIC_BACKEND_ORIGIN is inlined into the bundle AT BUILD TIME and
#    Next caches compiled output in .next/. If the origin changed since the
#    last run (a new demo IP, a switch between the two-laptop proxy and
#    localhost), a cached .next serves the OLD origin and every dashboard
#    fetch silently hits the wrong host. Discard it so the origin below is
#    always the one that actually ships.
echo "Building frontend (production mode, no dev-server HMR)..."
( cd frontend && rm -rf .next && npm run build )
( cd frontend && npm run start -- -p "$FRONTEND_PORT" ) &
pids+=($!)

# 3. Wait for both before starting the proxy.
echo "Waiting for backend on :$BACKEND_PORT ..."
until curl -sf "http://127.0.0.1:$BACKEND_PORT/health" -o /dev/null; do sleep 1; done
echo "Backend up."

echo "Waiting for frontend on :$FRONTEND_PORT ..."
until curl -sf "http://127.0.0.1:$FRONTEND_PORT" -o /dev/null; do sleep 1; done
echo "Frontend up."

echo ""
echo "KAAVAL core stack is live:"
echo "  Backend:   http://localhost:$BACKEND_PORT"
echo "  Frontend:  http://localhost:$FRONTEND_PORT"
echo ""
echo "NEXT: in another terminal on this laptop, start the TLS proxy:"
echo "  bash demo-tools/attacker/run-attacker.sh   # (sudo for port 443)"
echo "Then Laptop A browses to: https://kaaval.demo/demo"
echo "Press Ctrl+C to stop backend + frontend."

wait
