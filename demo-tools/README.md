# demo-tools/

Demo-*choreography* tooling — tooling **about** running the KAAVAL demo, kept as
a peer top-level folder (not part of `backend/`, `frontend/`, or `sdk/`, which
are the product being demoed). No security logic and no contracts live here.

## `attacker/` — Laptop B (attacker / host / SOC projector)
- `attacker-proxy.js` — TLS-terminating reverse proxy for `https://kaaval.demo`
  (LAN reengineering doc §3.5). Path-aware: backend paths → :8000, else → :3000.
- `replay-cookie.js` — capture/replay a stolen session cookie (Scenes 1-2).
- `tamper-request.js` — tamper/verbatim-replay a captured signed request (Scene 3).
- `certs/` — mkcert output for `kaaval.demo` (generated per machine, gitignored).
- `run-attacker.sh` — starts **only** the proxy (assumes the core stack is already
  up via `start-demo.sh`); leaves the replay/tamper scripts primed, not fired.

## `victim-setup/` — Laptop A (victim)
- `check-hosts.sh` — verify `kaaval.demo` → Laptop B's current LAN IP (strict).
- `check-cert-trust.sh` — verify the cert is trusted, no padlock warning (strict).
- `launch-browser.sh` — open Chrome at `https://kaaval.demo/demo`; `--fallback`
  uses the emergency insecure-origin override.
- `run-victim-setup.sh` — runs both checks in order, STOPS loudly on any failure,
  launches the browser only if both pass. Passes `--fallback` through.

## How the pieces run (division of labour)
1. Laptop B: `./start-demo.sh` — backend + frontend (the core stack).
2. Laptop B: `bash demo-tools/attacker/run-attacker.sh` — the proxy.
3. Laptop A: `bash demo-tools/victim-setup/run-victim-setup.sh` — pre-flight + browser.
