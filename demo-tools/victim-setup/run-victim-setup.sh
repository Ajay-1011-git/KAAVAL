#!/usr/bin/env bash
# =============================================================================
#  run-victim-setup.sh  —  pre-flight + launch, on Laptop A
# =============================================================================
#  Runs, in order:
#    1. check-hosts.sh      — kaaval.demo maps to Laptop B's current LAN IP
#    2. check-cert-trust.sh — https://kaaval.demo's cert is trusted (padlock)
#  and STOPS with a clear error if EITHER fails — it will not open a browser
#  onto an unresolvable hostname or an untrusted cert.
#
#  Only if BOTH pass does it call launch-browser.sh.
#
#  Flags:
#    --fallback   passed through to launch-browser.sh (emergency insecure-origin
#                 path). NOTE: check-cert-trust.sh will still fail first on an
#                 untrusted cert; if you are deliberately using the fallback,
#                 skip the cert gate with SKIP_CERT_CHECK=1 (documented below).
#
#  Env passthrough: HOSTS_FILE, EXPECTED_IP, SKIP_PING (to check-hosts.sh);
#    URL, PROXY_PORT, CA_CERT (to check-cert-trust.sh / launch-browser.sh);
#    DRY_RUN (to launch-browser.sh); SKIP_CERT_CHECK=1 to bypass the cert gate
#    ONLY when intentionally taking the --fallback path.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

FALLBACK_ARGS=()
for arg in "$@"; do
  case "$arg" in
    --fallback) FALLBACK_ARGS+=(--fallback) ;;
  esac
done

echo "=============================================================="
echo " KAAVAL victim-setup pre-flight (Laptop A)"
echo "=============================================================="

echo ""
echo "[1/2] Checking hosts entry..."
if ! bash "$HERE/check-hosts.sh"; then
  echo "" >&2
  echo "STOP: hosts check failed. Not launching the browser." >&2
  echo "  Fix kaaval.demo -> Laptop B's current LAN IP, then re-run." >&2
  exit 1
fi

echo ""
echo "[2/2] Checking certificate trust..."
if [ "${SKIP_CERT_CHECK:-0}" = "1" ]; then
  echo "[run-victim-setup] SKIP_CERT_CHECK=1 — skipping cert gate (fallback path)."
elif ! bash "$HERE/check-cert-trust.sh"; then
  echo "" >&2
  echo "STOP: certificate trust check failed. Not launching the browser." >&2
  echo "  Install mkcert's rootCA.pem into this machine's trust store (§3.3)." >&2
  echo "  As a LAST RESORT on stage, re-run with:  --fallback SKIP_CERT_CHECK=1" >&2
  exit 1
fi

echo ""
echo "Both checks passed. Launching browser..."
bash "$HERE/launch-browser.sh" ${FALLBACK_ARGS[@]+"${FALLBACK_ARGS[@]}"}
