#!/usr/bin/env bash
# =============================================================================
#  launch-browser.sh  —  open Chrome at the demo page (Laptop A)
# =============================================================================
#  Default: open Chrome at https://kaaval.demo/demo.
#  --fallback: EMERGENCY path only — open Chrome telling it to treat
#     https://kaaval.demo as a secure origin despite an untrusted cert
#     (--unsafely-treat-insecure-origin-as-secure). Use ONLY if the cert-trust
#     check failed on stage and cannot be fixed live; note it for a post-mortem.
#
#  Env overrides:
#    URL        full URL to open        (default https://kaaval.demo/demo)
#    PROXY_PORT if the proxy is not on 443 (builds https://kaaval.demo:PORT/demo)
#    DRY_RUN=1  print the exact command instead of launching (for tests)
set -uo pipefail

HOST="kaaval.demo"
FALLBACK=0
for arg in "$@"; do
  case "$arg" in
    --fallback) FALLBACK=1 ;;
    --dry-run)  DRY_RUN=1 ;;
  esac
done

if [ -n "${URL:-}" ]; then
  TARGET_URL="$URL"
elif [ -n "${PROXY_PORT:-}" ] && [ "${PROXY_PORT}" != "443" ]; then
  TARGET_URL="https://${HOST}:${PROXY_PORT}/demo"
else
  TARGET_URL="https://${HOST}/demo"
fi

# Cache-bust the HTML fetch by default. start-demo.sh rebuilds the frontend on
# every run, and Next serves hashed static assets as `immutable, max-age=1y`.
# So if this laptop loaded the demo during an earlier rehearsal, its Chrome
# profile can hold a stale /demo page whose asset hashes no longer exist after
# the rebuild — the page renders its HTML but none of its CSS, looking broken
# on stage. A unique query on the HTML URL forces a fresh page (which then
# references the current asset hashes) without touching cert trust or the
# user's profile. Set NO_CACHE_BUST=1 to opt out.
if [ "${NO_CACHE_BUST:-0}" != "1" ] && [ -z "${URL:-}" ]; then
  case "$TARGET_URL" in
    *\?*) TARGET_URL="${TARGET_URL}&_fresh=$(date +%s)" ;;
    *)    TARGET_URL="${TARGET_URL}?_fresh=$(date +%s)" ;;
  esac
fi

# Resolve a Chrome launcher + how to pass flags, per OS.
OS="$(uname -s 2>/dev/null || echo unknown)"
insecure_flag="--unsafely-treat-insecure-origin-as-secure=https://${HOST}"

build_cmd() {
  case "$OS" in
    Darwin)
      if [ "$FALLBACK" = "1" ]; then
        printf '%s' "open -na 'Google Chrome' --args '$insecure_flag' --user-data-dir=/tmp/kaaval-fallback-profile '$TARGET_URL'"
      else
        printf '%s' "open -a 'Google Chrome' '$TARGET_URL'"
      fi ;;
    Linux)
      local bin; bin="$(command -v google-chrome || command -v google-chrome-stable || command -v chromium || command -v chromium-browser || echo google-chrome)"
      if [ "$FALLBACK" = "1" ]; then
        printf '%s' "$bin '$insecure_flag' --user-data-dir=/tmp/kaaval-fallback-profile '$TARGET_URL'"
      else
        printf '%s' "$bin '$TARGET_URL'"
      fi ;;
    MINGW*|MSYS*|CYGWIN*)
      if [ "$FALLBACK" = "1" ]; then
        printf '%s' "start chrome $insecure_flag --user-data-dir=%TEMP%\\kaaval-fallback-profile \"$TARGET_URL\""
      else
        printf '%s' "start chrome \"$TARGET_URL\""
      fi ;;
    *) printf '%s' "xdg-open '$TARGET_URL'" ;;
  esac
}

CMD="$(build_cmd)"
[ "$FALLBACK" = "1" ] && echo "[launch-browser] EMERGENCY FALLBACK: launching with an insecure-origin override (note for post-mortem)."
echo "[launch-browser] opening: $TARGET_URL"

if [ "${DRY_RUN:-0}" = "1" ]; then
  echo "[launch-browser] DRY_RUN — would run:"
  echo "  $CMD"
  exit 0
fi

eval "$CMD"
