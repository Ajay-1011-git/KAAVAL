#!/usr/bin/env bash
# =============================================================================
#  check-cert-trust.sh  —  is https://kaaval.demo's cert TRUSTED here? (Laptop A)
# =============================================================================
#  The #1 on-stage failure mode from the guarantee checklist is a cert warning
#  on Laptop A. So this check is STRICT: it curls https://kaaval.demo using the
#  OS trust store and FAILS LOUDLY unless the certificate verifies cleanly (the
#  padlock). A reachable-but-untrusted cert is a FAIL, not a warning.
#
#  Env overrides:
#    URL       full URL to test        (default https://kaaval.demo/health)
#    PROXY_PORT if the proxy is not on 443 (builds https://kaaval.demo:PORT/health)
#    CA_CERT   path to a CA bundle to trust — LOCAL SELF-TEST ONLY (simulates the
#              mkcert CA already being in the OS trust store). Do NOT set this on
#              the real Laptop A: there the whole point is to test OS trust.
#    RESOLVE   curl --resolve spec 'host:port:ip' — LOCAL SELF-TEST ONLY, to
#              reach the proxy before kaaval.demo is in /etc/hosts. Not needed
#              on the real Laptop A (kaaval.demo already resolves there).
set -uo pipefail

HOST="kaaval.demo"
if [ -n "${URL:-}" ]; then
  TEST_URL="$URL"
elif [ -n "${PROXY_PORT:-}" ] && [ "${PROXY_PORT}" != "443" ]; then
  TEST_URL="https://${HOST}:${PROXY_PORT}/health"
else
  TEST_URL="https://${HOST}/health"
fi

fail() { echo "FAIL: $*" >&2; exit 1; }

CA_ARGS=()
if [ -n "${CA_CERT:-}" ]; then
  echo "[check-cert-trust] (self-test) trusting CA bundle: $CA_CERT"
  CA_ARGS=(--cacert "$CA_CERT")
fi
if [ -n "${RESOLVE:-}" ]; then
  echo "[check-cert-trust] (self-test) curl --resolve $RESOLVE"
  CA_ARGS+=(--resolve "$RESOLVE")
fi

echo "[check-cert-trust] verifying certificate at $TEST_URL"
# --fail: non-2xx/3xx is an error; strict TLS (no -k). Capture curl's exit code
# to distinguish 'untrusted cert' (60) from 'cannot connect' (7).
set +e
# ${CA_ARGS[@]+"${CA_ARGS[@]}"} — not "${CA_ARGS[@]}" — because macOS ships bash
# 3.2, where expanding an EMPTY array under `set -u` (set at the top of this
# script) aborts with "unbound variable". CA_ARGS is empty on the real Laptop A
# (no CA_CERT/RESOLVE self-test overrides), so the plain form crashed the cert
# check before it ever ran curl. This idiom expands to nothing when empty and
# to the quoted elements when set — the same one run-victim-setup.sh already
# uses for its FALLBACK_ARGS.
curl --fail --silent --show-error ${CA_ARGS[@]+"${CA_ARGS[@]}"} -o /dev/null "$TEST_URL"
code=$?
set -e 2>/dev/null || true

case "$code" in
  0)  echo "PASS: certificate for $HOST is trusted — clean padlock, no warning." ;;
  60|51|58|59|77|83)
      fail "certificate for $HOST is NOT trusted (curl $code).
       Install mkcert's rootCA.pem into this machine's OS trust store BEFORE demo day
       (KAAVAL_Demo_LAN_Reengineering.md §3.3). This cannot be safely fixed live." ;;
  7|6|28)
      fail "cannot reach $TEST_URL (curl $code).
       Is the attacker proxy running (run-attacker.sh) and is kaaval.demo pointed at
       Laptop B? Run check-hosts.sh first." ;;
  *)  fail "certificate/endpoint check failed (curl exit $code) for $TEST_URL." ;;
esac
