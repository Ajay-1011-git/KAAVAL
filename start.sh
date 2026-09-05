#!/usr/bin/env bash
#
# KAAVAL — start the whole project.
#
#   ./start.sh
#
# Brings up the FastAPI backend (gateway, Radar, Guardian, Chronicle, SSE
# stream) and the Next.js dashboard, after checking that everything they
# depend on is actually in place. Ctrl+C stops both.
#
# Options:
#   --skip-install    don't run npm install / pip install, just start
#   --backend-only    no dashboard
#   --help
#
# Environment overrides:
#   BACKEND_PORT   (default 8000)
#   FRONTEND_PORT  (default 3000)
#
# Written for bash 3.2, which is what macOS ships — no associative arrays,
# no ${var,,}.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
ROOT="$(pwd)"

# --- platform portability ---------------------------------------------
# The host role may run on macOS/Linux OR on Windows (via Git Bash / MSYS2),
# so nothing below assumes a single venv layout, python name, or port tool.
# On Windows a venv keeps its interpreter at Scripts/python.exe, ships `python`
# rather than `python3`, and has no `lsof`.
case "$(uname -s 2>/dev/null || echo unknown)" in
  MINGW*|MSYS*|CYGWIN*) IS_WINDOWS=1 ;;
  *)                    IS_WINDOWS=0 ;;
esac

# Path to a venv's interpreter, given the venv directory.
venv_python() {
  if [ "$IS_WINDOWS" -eq 1 ]; then printf '%s/Scripts/python.exe' "$1"
  else printf '%s/bin/python' "$1"; fi
}

BACKEND_PORT="${BACKEND_PORT:-8000}"
FRONTEND_PORT="${FRONTEND_PORT:-3000}"
SKIP_INSTALL=0
BACKEND_ONLY=0

BACKEND_PID=""
FRONTEND_PID=""

# --- output helpers ---------------------------------------------------

if [ -t 1 ]; then
  BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GREEN=$'\033[32m'
  YELLOW=$'\033[33m'; CYAN=$'\033[36m'; RESET=$'\033[0m'
else
  BOLD=""; DIM=""; RED=""; GREEN=""; YELLOW=""; CYAN=""; RESET=""
fi

step()  { printf "%s==>%s %s\n" "$CYAN" "$RESET" "$1"; }
ok()    { printf "    %s✓%s %s\n" "$GREEN" "$RESET" "$1"; }
warn()  { printf "    %s!%s %s\n" "$YELLOW" "$RESET" "$1"; }
die()   { printf "\n%serror:%s %s\n\n" "$RED" "$RESET" "$1" >&2; exit 1; }

# --- argument parsing -------------------------------------------------

while [ $# -gt 0 ]; do
  case "$1" in
    --skip-install) SKIP_INSTALL=1 ;;
    --backend-only) BACKEND_ONLY=1 ;;
    -h|--help)
      sed -n '3,21p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
  shift
done

# --- shutdown ---------------------------------------------------------

shutdown() {
  # Preserve the failing status. Without this the trap's own exit overwrote
  # die()'s exit 1 with 0, so a hard preflight failure looked like success to
  # anything scripting against this (CI, a wrapper, a Makefile).
  status="${1:-0}"

  # Stop being re-entrant: Ctrl+C during shutdown shouldn't run this twice.
  trap - INT TERM EXIT

  # Nothing started yet (a preflight failure) — don't print a shutdown banner
  # for servers that never existed.
  if [ -z "${BACKEND_PID:-}" ] && [ -z "${FRONTEND_PID:-}" ]; then
    exit "$status"
  fi

  printf "\n"
  step "Shutting down"
  for pid_name in FRONTEND_PID BACKEND_PID; do
    eval "pid=\${$pid_name:-}"
    if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
      # Kill the whole process group: `next dev` and `uvicorn --reload` both
      # spawn children that would otherwise keep the port bound.
      kill -TERM -"$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
    fi
  done
  sleep 1
  for pid_name in FRONTEND_PID BACKEND_PID; do
    eval "pid=\${$pid_name:-}"
    if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
      kill -KILL -"$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
    fi
  done
  ok "stopped"
  exit "$status"
}
# $? at trap time is the real exit status. A deliberate Ctrl+C is not a
# failure, so INT/TERM report success.
trap 'shutdown $?' EXIT
trap 'shutdown 0' INT TERM

# --- preflight --------------------------------------------------------

port_in_use() {
  if [ "$IS_WINDOWS" -eq 1 ]; then
    # Git Bash has no lsof; netstat is present on every Windows.
    netstat -ano -p tcp 2>/dev/null | grep -Eq "[:.]$1[[:space:]].*LISTENING"
  else
    lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
  fi
}

wait_for_http() {
  # wait_for_http <url> <timeout_seconds> <pid> <label>
  url="$1"; timeout="$2"; pid="$3"; label="$4"
  waited=0
  while [ "$waited" -lt "$timeout" ]; do
    if ! kill -0 "$pid" 2>/dev/null; then
      return 1  # process died; caller prints the log
    fi
    if curl -fsS -o /dev/null --max-time 2 "$url" 2>/dev/null; then
      return 0
    fi
    sleep 1
    waited=$((waited + 1))
  done
  return 1
}

step "Checking prerequisites"

# The system interpreter used to CREATE a venv when none exists yet: `python3`
# on Unix, `python` (or the `py` launcher) on Windows.
if [ "$IS_WINDOWS" -eq 1 ]; then
  if   command -v python >/dev/null 2>&1; then SYS_PY="python"
  elif command -v py     >/dev/null 2>&1; then SYS_PY="py"
  else die "python not found on PATH (install Python and re-open the shell)"; fi
else
  command -v python3 >/dev/null 2>&1 || die "python3 not found on PATH"
  SYS_PY="python3"
fi
command -v node    >/dev/null 2>&1 || die "node not found on PATH"
command -v npm     >/dev/null 2>&1 || die "npm not found on PATH"
command -v curl    >/dev/null 2>&1 || die "curl not found on PATH"
ok "$("$SYS_PY" --version 2>&1), node $(node --version), npm $(npm --version)"

# Root .env — the backend reads it via backend/__init__.py.
if [ ! -f .env ]; then
  cp .env.example .env
  warn "created .env from .env.example (GROQ_API_KEY is blank, so Chronicle"
  warn "  will use its deterministic fallback until you add a key)"
else
  ok ".env present"
fi

# Next.js only loads env from frontend/, never the repo root. Without this the
# dashboard silently renders bundled fixtures instead of live data — it looks
# completely real, which is the worst possible failure mode for a security
# demo. The UI now labels it, but it's better to just not be in that state.
FRONTEND_ENV="frontend/.env.local"
BACKEND_ORIGIN="http://localhost:${BACKEND_PORT}"
if [ ! -f "$FRONTEND_ENV" ]; then
  printf 'NEXT_PUBLIC_BACKEND_ORIGIN=%s\nNEXT_PUBLIC_WEBAUTHN_RP_ID=localhost\n' \
    "$BACKEND_ORIGIN" > "$FRONTEND_ENV"
  ok "created $FRONTEND_ENV pointing at $BACKEND_ORIGIN"
elif ! grep -q "NEXT_PUBLIC_BACKEND_ORIGIN=${BACKEND_ORIGIN}$" "$FRONTEND_ENV"; then
  warn "$FRONTEND_ENV does not point at $BACKEND_ORIGIN —"
  warn "  the dashboard may render fixtures or call the wrong port"
else
  ok "$FRONTEND_ENV points at the backend"
fi

# --- python environment ----------------------------------------------

step "Backend environment"

# The README creates .venv at the repo root; this repo has historically also
# had backend/.venv. Accept either rather than making one of them wrong.
VENV=""
for candidate in "$ROOT/.venv" "$ROOT/backend/.venv"; do
  if [ -x "$(venv_python "$candidate")" ] || [ -f "$(venv_python "$candidate")" ]; then
    VENV="$candidate"; break
  fi
done

if [ -z "$VENV" ]; then
  if [ "$SKIP_INSTALL" -eq 1 ]; then
    die "no virtualenv found and --skip-install was given"
  fi
  step "  creating virtualenv at .venv"
  "$SYS_PY" -m venv "$ROOT/.venv"
  VENV="$ROOT/.venv"
fi
PY="$(venv_python "$VENV")"
ok "using $(printf '%s' "$VENV" | sed "s#^$ROOT/#./#")"

if ! "$PY" -c "import fastapi, uvicorn, webauthn, groq" >/dev/null 2>&1; then
  if [ "$SKIP_INSTALL" -eq 1 ]; then
    die "backend dependencies missing and --skip-install was given"
  fi
  step "  installing backend requirements"
  "$PY" -m pip install -q --upgrade pip
  "$PY" -m pip install -q -r backend/requirements.txt
fi
ok "backend dependencies present"

# --- sdk --------------------------------------------------------------

if [ "$BACKEND_ONLY" -eq 0 ]; then
  step "Browser SDK"
  # Build order matters: the frontend imports the SDK's COMPILED output via
  # `file:../sdk`, so an unbuilt or stale dist/ breaks the frontend build with
  # a module-not-found that looks like a frontend problem.
  if [ "$SKIP_INSTALL" -eq 0 ]; then
    if [ ! -d sdk/node_modules ]; then
      step "  npm install (sdk)"
      (cd sdk && npm install --silent)
    fi
    step "  building sdk"
    (cd sdk && npm run build --silent >/dev/null)
  fi
  [ -f sdk/dist/index.js ] || die "sdk/dist not built — run: cd sdk && npm install && npm run build"
  ok "sdk built"

  step "Dashboard environment"
  if [ "$SKIP_INSTALL" -eq 0 ]; then
    # The linked SDK lives in frontend/node_modules/@kaaval — a node_modules
    # that predates the link installs fine but fails at build time.
    if [ ! -d frontend/node_modules ] || [ ! -e frontend/node_modules/@kaaval/sdk ]; then
      step "  npm install (frontend)"
      (cd frontend && npm install --silent)
    fi
  fi
  [ -d frontend/node_modules ] || die "frontend/node_modules missing — run: cd frontend && npm install"
  ok "dashboard dependencies present"
fi

# --- ports ------------------------------------------------------------

step "Checking ports"
if port_in_use "$BACKEND_PORT"; then
  die "port $BACKEND_PORT is already in use.
  Something else is bound to it — stop it, or start with:
      BACKEND_PORT=8010 ./start.sh"
fi
ok "backend port $BACKEND_PORT free"

if [ "$BACKEND_ONLY" -eq 0 ]; then
  if port_in_use "$FRONTEND_PORT"; then
    die "port $FRONTEND_PORT is already in use.
  Stop it, or start with:
      FRONTEND_PORT=3010 ./start.sh
  (note: WEBAUTHN_RP_ORIGIN in .env must match the dashboard's origin, or
   the passkey demo at /demo will be rejected)"
  fi
  ok "dashboard port $FRONTEND_PORT free"
fi

mkdir -p .run
BACKEND_LOG=".run/backend.log"
FRONTEND_LOG=".run/frontend.log"

# --- backend ----------------------------------------------------------

step "Starting backend on :$BACKEND_PORT"
# setsid-equivalent: run in its own process group so shutdown can take the
# reloader's children with it.
set -m
"$PY" -m uvicorn backend.main:app --port "$BACKEND_PORT" --reload > "$BACKEND_LOG" 2>&1 &
BACKEND_PID=$!
set +m

if ! wait_for_http "http://127.0.0.1:${BACKEND_PORT}/health" 40 "$BACKEND_PID" "backend"; then
  printf "\n%s--- %s ---%s\n" "$DIM" "$BACKEND_LOG" "$RESET"
  tail -25 "$BACKEND_LOG" || true
  die "backend failed to become healthy"
fi
ok "backend healthy — $(curl -fsS "http://127.0.0.1:${BACKEND_PORT}/health")"

# Report which narration path Chronicle will actually take, rather than
# letting a blank key look like a live LLM at demo time.
if "$PY" - <<'PYEOF' 2>/dev/null
import os, sys
sys.path.insert(0, ".")
import backend  # loads .env
key = (os.getenv("GROQ_API_KEY") or os.getenv("GROQ_API") or os.getenv("LLM_API_KEY") or "").strip()
forced = os.getenv("CHRONICLE_FALLBACK_MODE", "false").strip().lower() in ("1", "true", "yes", "on")
sys.exit(0 if key and not forced else 1)
PYEOF
then
  ok "Chronicle: live narration (Groq key configured)"
else
  warn "Chronicle: deterministic fallback (no GROQ_API_KEY, or fallback forced)"
fi

# --- frontend ---------------------------------------------------------

if [ "$BACKEND_ONLY" -eq 0 ]; then
  step "Starting dashboard on :$FRONTEND_PORT"
  set -m
  (cd frontend && npm run dev -- --port "$FRONTEND_PORT") > "$FRONTEND_LOG" 2>&1 &
  FRONTEND_PID=$!
  set +m

  if ! wait_for_http "http://127.0.0.1:${FRONTEND_PORT}" 90 "$FRONTEND_PID" "dashboard"; then
    printf "\n%s--- %s ---%s\n" "$DIM" "$FRONTEND_LOG" "$RESET"
    tail -25 "$FRONTEND_LOG" || true
    die "dashboard failed to start"
  fi
  ok "dashboard responding"
fi

# --- ready ------------------------------------------------------------

printf "\n%sKAAVAL is running%s\n\n" "$BOLD$GREEN" "$RESET"
if [ "$BACKEND_ONLY" -eq 0 ]; then
printf "  %sDashboard%s      http://localhost:%s\n"        "$BOLD" "$RESET" "$FRONTEND_PORT"
printf "  %sBrowser demo%s   http://localhost:%s/demo\n"   "$BOLD" "$RESET" "$FRONTEND_PORT"
fi
printf "  %sAPI docs%s       http://localhost:%s/docs\n"   "$BOLD" "$RESET" "$BACKEND_PORT"
printf "  %sEvent stream%s   http://localhost:%s/events/stream\n" "$BOLD" "$RESET" "$BACKEND_PORT"
printf "\n  %sRun the attack demo in another terminal:%s\n" "$DIM" "$RESET"
printf "    %s -m backend.attacker_console.replay --base-url http://127.0.0.1:%s\n" \
  "$(printf '%s' "$PY" | sed "s#^$ROOT/#./#")" "$BACKEND_PORT"
printf "    %s -m backend.attacker_console.oauth_consent --base-url http://127.0.0.1:%s\n" \
  "$(printf '%s' "$PY" | sed "s#^$ROOT/#./#")" "$BACKEND_PORT"
printf "\n  %slogs: %s, %s%s\n" "$DIM" "$BACKEND_LOG" "$FRONTEND_LOG" "$RESET"
printf "  %sCtrl+C to stop%s\n\n" "$DIM" "$RESET"

# Wait on whichever servers are running; if one dies, report it and stop.
while true; do
  if [ -n "$BACKEND_PID" ] && ! kill -0 "$BACKEND_PID" 2>/dev/null; then
    warn "backend exited — see $BACKEND_LOG"
    tail -15 "$BACKEND_LOG" || true
    break
  fi
  if [ -n "$FRONTEND_PID" ] && ! kill -0 "$FRONTEND_PID" 2>/dev/null; then
    warn "dashboard exited — see $FRONTEND_LOG"
    tail -15 "$FRONTEND_LOG" || true
    break
  fi
  sleep 2
done
