#!/usr/bin/env bash
# =============================================================================
#  check-hosts.sh  —  is kaaval.demo pointed at Laptop B's CURRENT LAN IP? (Laptop A)
# =============================================================================
#  FAILS LOUDLY (non-zero exit) — never a silent pass — if:
#    * there is no kaaval.demo entry in the hosts file, or
#    * it points at a loopback address (127.x / ::1) — that means "myself",
#      not Laptop B, which is the classic stale/wrong entry, or
#    * an EXPECTED_IP was given and the entry does not match it, or
#    * kaaval.demo is unreachable (ping fails).
#
#  Env overrides:
#    HOSTS_FILE   path to hosts file (default: OS-appropriate)
#    EXPECTED_IP  Laptop B's current LAN IP to require an exact match against
#    SKIP_PING    set to 1 to skip the reachability ping (check logic only)
set -uo pipefail

HOST="kaaval.demo"

# Default hosts file per OS.
case "$(uname -s 2>/dev/null || echo unknown)" in
  MINGW*|MSYS*|CYGWIN*) DEFAULT_HOSTS="${SYSTEMROOT:-C:/Windows}/System32/drivers/etc/hosts" ;;
  *)                    DEFAULT_HOSTS="/etc/hosts" ;;
esac
HOSTS_FILE="${HOSTS_FILE:-$DEFAULT_HOSTS}"

fail() { echo "FAIL: $*" >&2; exit 1; }

echo "[check-hosts] hosts file: $HOSTS_FILE"
[ -r "$HOSTS_FILE" ] || fail "cannot read hosts file $HOSTS_FILE"

# Grab the IP mapped to kaaval.demo (ignore comments; last matching wins, as the
# resolver would use it). Match kaaval.demo as a whole word.
mapped_ip="$(grep -vE '^\s*#' "$HOSTS_FILE" \
  | awk -v h="$HOST" '{ for (i=2;i<=NF;i++) if ($i==h) { ip=$1 } } END { if (ip!="") print ip }')"

[ -n "$mapped_ip" ] || fail "no '$HOST' entry in $HOSTS_FILE — add:  <Laptop-B-LAN-IP>   $HOST"
echo "[check-hosts] $HOST -> $mapped_ip"

case "$mapped_ip" in
  127.*|::1|0.0.0.0)
    fail "$HOST points at loopback ($mapped_ip). That is THIS machine, not Laptop B.
       For the two-laptop demo it must be Laptop B's current LAN IP.
       Find it on Laptop B ('ipconfig getifaddr en0' / 'hostname -I') and update $HOSTS_FILE." ;;
esac

if [ -n "${EXPECTED_IP:-}" ] && [ "$mapped_ip" != "$EXPECTED_IP" ]; then
  fail "$HOST -> $mapped_ip but Laptop B's current IP is $EXPECTED_IP (stale entry). Update $HOSTS_FILE."
fi

if [ "${SKIP_PING:-0}" = "1" ]; then
  echo "[check-hosts] SKIP_PING set — not pinging."
else
  # -c1 one packet; timeout flag differs by platform.
  if ping -c1 -W1 "$mapped_ip" >/dev/null 2>&1 || ping -c1 -t1 "$mapped_ip" >/dev/null 2>&1; then
    echo "[check-hosts] ping $mapped_ip OK"
  else
    fail "$mapped_ip (mapped from $HOST) is not reachable. Is Laptop B on the same network and powered up?
       Re-check Laptop B's IP and this hosts entry."
  fi
fi

echo "PASS: $HOST resolves to a non-loopback, reachable address ($mapped_ip)."
