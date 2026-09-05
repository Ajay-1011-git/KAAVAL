#!/usr/bin/env bash
# stop-demo.sh — best-effort kill switch for a stack started outside a live
# start-demo.sh (its own Ctrl+C trap is the normal path). Kills the demo
# processes by the ports they listen on.
set -uo pipefail
PROXY_PORT="${PROXY_PORT:-443}"
BACKEND_PORT="${BACKEND_PORT:-8000}"
FRONTEND_PORT="${FRONTEND_PORT:-3000}"
for port in "$PROXY_PORT" "$BACKEND_PORT" "$FRONTEND_PORT"; do
  pids="$(lsof -ti tcp:"$port" 2>/dev/null || true)"
  if [ -n "$pids" ]; then
    echo "killing PIDs on :$port -> $pids"
    kill $pids 2>/dev/null || true
  fi
done
echo "done."
