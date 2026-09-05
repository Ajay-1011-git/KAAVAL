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
#
#  Override any of these before running:
#    PROXY_PORT   TLS port for the proxy   (default 443; needs sudo)
#    BACKEND_PORT FastAPI port             (default 8000)
#    FRONTEND_PORT Next.js port            (default 3000)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

BACKEND_PORT="${BACKEND_PORT:-8000}"
FRONTEND_PORT="${FRONTEND_PORT:-3000}"

echo "Starting KAAVAL demo stack (repo: $REPO_ROOT)..."

# Prefer the repo-root venv interpreter directly so we don't depend on the
# caller having activated it. The host role may run on macOS/Linux or on
# Windows (Git Bash), where the venv interpreter lives in Scripts/python.exe.
case "$(uname -s 2>/dev/null || echo unknown)" in
  MINGW*|MSYS*|CYGWIN*) VENV_PY="$REPO_ROOT/.venv/Scripts/python.exe" ;;
  *)                    VENV_PY="$REPO_ROOT/.venv/bin/python" ;;
esac
if [ -x "$VENV_PY" ] || [ -f "$VENV_PY" ]; then
  PY="$VENV_PY"
else
  echo "ERROR: $REPO_ROOT/.venv not found. Create it (README §1) first." >&2
  exit 1
fi

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

# 2. Frontend (Next.js dashboard + /demo)
( cd frontend && npm run dev -- -p "$FRONTEND_PORT" ) &
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
