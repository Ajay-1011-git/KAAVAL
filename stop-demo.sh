#!/usr/bin/env bash
# stop-demo.sh — best-effort kill switch for a stack started outside a live
# start-demo.sh (its own Ctrl+C trap is the normal path). Kills the demo
# processes by the ports they listen on.
set -uo pipefail
PROXY_PORT="${PROXY_PORT:-443}"
BACKEND_PORT="${BACKEND_PORT:-8000}"
FRONTEND_PORT="${FRONTEND_PORT:-3000}"

# Windows (Git Bash) has neither lsof nor a POSIX kill that reaps children, so
# find the listening PID with netstat and end it with taskkill; Unix uses lsof.
case "$(uname -s 2>/dev/null || echo unknown)" in
  MINGW*|MSYS*|CYGWIN*) IS_WINDOWS=1 ;;
  *)                    IS_WINDOWS=0 ;;
esac

for port in "$PROXY_PORT" "$BACKEND_PORT" "$FRONTEND_PORT"; do
  if [ "$IS_WINDOWS" -eq 1 ]; then
    pids="$(netstat -ano -p tcp 2>/dev/null \
      | grep -E "[:.]$port[[:space:]].*LISTENING" \
      | awk '{print $NF}' | sort -u)"
    for pid in $pids; do
      [ -n "$pid" ] && [ "$pid" != "0" ] || continue
      echo "killing PID on :$port -> $pid"
      taskkill //F //PID "$pid" >/dev/null 2>&1 || true
    done
  else
    pids="$(lsof -ti tcp:"$port" 2>/dev/null || true)"
    if [ -n "$pids" ]; then
      echo "killing PIDs on :$port -> $pids"
      kill $pids 2>/dev/null || true
    fi
  fi
done
echo "done."
