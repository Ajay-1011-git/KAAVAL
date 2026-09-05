#!/usr/bin/env bash
# =============================================================================
#  run-attacker.sh  —  bring up ONLY the attacker proxy (Laptop B)
# =============================================================================
#  Starts the TLS-terminating reverse proxy (attacker-proxy.js) in front of the
#  already-running core stack. It does NOT start the backend or frontend — that
#  is start-demo.sh's job. Run start-demo.sh first, then this.
#
#  replay-cookie.js and tamper-request.js are left PRIMED but NOT executed:
#  they are fired by hand, on cue, during Scenes 1-3 (see the printout below).
#
#  Env overrides:
#    PROXY_PORT   TLS listen port   (default 443 — needs sudo; use 8443 to test)
#    TARGET       frontend origin   (default http://localhost:3000)
#    BACKEND      gateway origin    (default http://localhost:8000)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

PROXY_PORT="${PROXY_PORT:-443}"
TARGET="${TARGET:-http://localhost:3000}"
BACKEND="${BACKEND:-http://localhost:8000}"
CERT_DIR="$HERE/certs"

# Certs must exist (mkcert on Laptop B — see certs/README.md).
if [ ! -f "$CERT_DIR/kaaval.demo.pem" ] || [ ! -f "$CERT_DIR/kaaval.demo-key.pem" ]; then
  echo "ERROR: TLS cert pair not found in $CERT_DIR" >&2
  echo "  Generate on this laptop:  mkcert -install && mkcert kaaval.demo" >&2
  echo "  then move kaaval.demo.pem + kaaval.demo-key.pem into $CERT_DIR/" >&2
  exit 1
fi

echo "Starting attacker proxy (assumes backend+frontend already running via start-demo.sh)..."

# TARGET sets the frontend target; backend path prefixes still route to $BACKEND
# via the proxy's BACKEND_TARGET (that path-awareness is what lets a single
# https://kaaval.demo origin front both services).
PORT="$PROXY_PORT" TARGET="$TARGET" BACKEND_TARGET="$BACKEND" CERT_DIR="$CERT_DIR" \
  node attacker-proxy.js &
PROXY_PID=$!
trap 'kill "$PROXY_PID" 2>/dev/null || true' EXIT INT TERM

# Wait until the proxy is actually accepting TLS connections (any HTTP response,
# even 502, proves it is listening) before declaring ready.
ready=""
for _ in $(seq 1 30); do
  # Any HTTP response (even 502 when the backend is not up) proves the proxy is
  # listening. "000" / non-zero curl means connection refused -> not up yet.
  code="$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1:${PROXY_PORT}/" 2>/dev/null || true)"
  if [ -n "$code" ] && [ "$code" != "000" ]; then ready="yes"; break; fi
  sleep 0.5
done

PORT_SUFFIX=""; [ "$PROXY_PORT" != "443" ] && PORT_SUFFIX=":${PROXY_PORT}"
echo ""
echo "=============================================================="
if [ -n "$ready" ]; then
  echo " ATTACKER PROXY LIVE"
else
  echo " ATTACKER PROXY STARTED (readiness probe inconclusive — check log above)"
fi
echo "   Laptop A browses to:  https://kaaval.demo${PORT_SUFFIX}/demo"
echo "   SOC dashboard (here): https://kaaval.demo${PORT_SUFFIX}/"
echo ""
echo " Fire these BY HAND, on cue, during the scenes (do not auto-run):"
echo "   Scene 1 (baseline theft works):"
echo "     node replay-cookie.js capture <proxy log>   # or COOKIE=<val>"
echo "     node replay-cookie.js replay --mode baseline"
echo "   Scene 2 (PulseLock blocks the same cookie):"
echo "     node replay-cookie.js replay --mode protected     # -> proof_absent"
echo "   Scene 3 (tamper / verbatim replay of a signed request):"
echo "     node tamper-request.js                            # -> body_hash_mismatch"
echo "     node tamper-request.js --verbatim                 # -> nonce_reused"
echo ""
echo " Ctrl+C stops the proxy (leaves backend/frontend running)."
echo "=============================================================="

wait "$PROXY_PID"
