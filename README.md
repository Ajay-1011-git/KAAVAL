# KAAVAL

Session cookies stolen by an AiTM (Adversary-in-the-Middle) reverse proxy are
bearer credentials that nobody re-checks. KAAVAL binds every authenticated
request to a **non-exportable, per-session browser key pair** and requires a
fresh signature on each one, so a stolen cookie stops being enough.

The core idea is **PulseLock**: the browser generates an ECDSA P-256 key pair
whose private key never leaves the Web Crypto secure boundary, and every
protected request carries a signature over a fixed canonical string. The
gateway re-verifies that signature — plus a single-use nonce, a strictly
increasing sequence, and a freshness window — on **every** request. A cookie
lifted off the wire has no key behind it, so it fails.

Around that core sit three deterministic services and a narrator:

| Module | Lives in | Does |
|---|---|---|
| **PulseLock — browser SDK** | `sdk/` | Non-exportable session keys, WebAuthn ceremonies, request canonicalization + signing |
| **PulseLock — gateway** | `backend/gateway/` | Session-to-key binding, nonce issuance, seven-step verification, replay prevention, the demo app, the SSE event stream |
| **Radar** | `backend/radar/` | Deterministic exposure scoring over a simulated org — every point traces to a named check |
| **Guardian** | `backend/guardian/` | Deterministic OAuth-consent and device-code policy — device-code is deny-by-default |
| **Chronicle + dashboard** | `backend/chronicle/`, `frontend/` | Live event feed, incident timeline, and plain-language incident narration (Groq, with a deterministic fallback) |

Everything runs in **one FastAPI process over one SQLite database** with an
in-process event bus — no Redis, no distributed infrastructure. Two design
lines are load-bearing and stated in the PRD:

- **No opaque scores stand in for proof.** Every Radar finding and every
  Guardian block names its exact source check (PRD NFR-2). No ML risk model,
  no `confidence: 0.73` anywhere.
- **No behavioral biometrics or fingerprinting** (PRD §4.2). Supporting
  signals (new device, new country) may inform investigation or trigger
  step-up auth; they are never treated as identity.

Working across more than one module? Read
[`KAAVAL_Team_Integration_Plan.md`](KAAVAL_Team_Integration_Plan.md) first —
it defines module ownership, the frozen contracts, and the merge order.

---

## How a request flows

```text
Browser (sdk/)                     Gateway (backend/gateway/)
──────────────                     ─────────────────────────
generateSessionKeyPair()  ──┐
registerPasskey() ──────────┼──▶  WebAuthn register/login → session bound to public key
loginWithPasskey()  ────────┘

kaavalFetch(POST /api/transfer)
  1. POST /auth/nonce         ──▶  issue single-use nonce
  2. build canonical string        session_id\nmethod\norigin\npath\n
     over the 8 fields               body_hash\nnonce\nsequence\ntimestamp
  3. sign with the private key
  4. send + X-KAAVAL-Proof    ──▶  verify_signed_request() runs 7 checks in order:
                                     1 session active      → session_inactive
                                     2 signature valid      → signature_invalid
                                     3 method/origin/path   → request_mismatch
                                     4 body_hash matches    → body_hash_mismatch
                                     5 nonce issued+unused  → nonce_reused
                                     6 sequence increasing  → sequence_invalid
                                     7 timestamp in window  → timestamp_stale
                                   each writes a SecurityEvent → SSE → dashboard
```

The canonical string, its field order, and the seven-check order are frozen in
[`KAAVAL_TRD.md`](KAAVAL_TRD.md) §6.1 and implemented in
[`backend/gateway/verify.py`](backend/gateway/verify.py). The SDK builds the
identical string in [`sdk/src/canonical.ts`](sdk/src/canonical.ts); the gateway
parses it literally, so the two must stay byte-aligned.

All five data models — `SignedRequestEnvelope`, `SecurityEvent`,
`RadarFinding`, `RadarReport`, `IncidentExplanation` — are defined once in
[`backend/contracts.py`](backend/contracts.py) and are frozen. Nothing crosses
a module boundary as an ad-hoc dict.

---

## Prerequisites

- **Python 3.11+** (developed on 3.13)
- **Node.js 20+** (developed on 22 — the attacker tools use the global `fetch`)
- A browser with **passkey support** for the live demo (Chrome, Edge, or Safari)
- For the two-laptop LAN demo only: **mkcert**, and two machines on the same LAN

---

## Setup

### 1. Environment file

```bash
cp .env.example .env
```

`.env` is gitignored. `.env.example` is tracked, so **never put a real key in
it**. Two format rules that will bite you otherwise:

- A **blank** value must not carry a trailing `# comment` on the same line —
  `python-dotenv` reads the comment text as the value. Comments for blank keys
  go on their own line above.
- `WEBAUTHN_RP_ORIGIN` is the origin the **demo page** is served from
  (`http://localhost:3000`), not the backend's. WebAuthn puts the page origin
  in `clientDataJSON` and the gateway compares against exactly that.

The variables you are most likely to touch:

| Variable | Default | Purpose |
|---|---|---|
| `WEBAUTHN_RP_ID` | `localhost` | Relying-party id; must equal `NEXT_PUBLIC_WEBAUTHN_RP_ID` |
| `WEBAUTHN_RP_ORIGIN` | `http://localhost:3000` | Origin the passkey ceremony is checked against |
| `NONCE_TTL_SECONDS` | `30` | Single-use nonce validity window |
| `REQUEST_FRESHNESS_WINDOW_SECONDS` | `30` | Timestamp check window (TRD §6.1 step 7) |
| `KAAVAL_DEFAULT_MODE` | `protected` | Demo app default when `?mode=` is absent: `baseline` \| `protected` |
| `GROQ_API_KEY` | *(blank)* | Chronicle's LLM key; blank ⇒ deterministic fallback |
| `CHRONICLE_LLM_MODEL` | `qwen/qwen3.8-27b` | Verify against `GET /openai/v1/models` for your account |
| `CHRONICLE_FALLBACK_MODE` | `false` | Set `true` to force the scripted narrative, for rehearsal |

Chronicle's narration runs on **Groq**. Leave `GROQ_API_KEY` blank and it uses
a deterministic fallback narrative instead of a live call — the demo works
either way, it just stops being LLM-generated. Chronicle never blocks a
request: an unset key, a timeout, or any ungrounded response degrades to
[`backend/chronicle/fallback.py`](backend/chronicle/fallback.py).

### 2. Backend

```bash
python -m venv .venv

# macOS/Linux
source .venv/bin/activate && pip install -r backend/requirements.txt

# Windows
.venv\Scripts\python -m pip install -r backend\requirements.txt
```

Every command below assumes an **activated** venv (`source .venv/bin/activate`
on macOS/Linux, `.venv\Scripts\activate` on Windows) and uses plain `python`.
If you'd rather not activate, replace `python` with the venv's own interpreter
path directly: `.venv/bin/python` (macOS/Linux) or `.venv\Scripts\python`
(Windows).

### 3. SDK (build before the frontend — the frontend imports its compiled output)

```bash
cd sdk
npm install
npm run build
cd ..
```

### 4. Frontend

```bash
cd frontend
npm install          # also links the local SDK via `file:../sdk`
cd ..
```

The dashboard reads two public variables. Next.js only loads them from
`frontend/`, so put them in `frontend/.env.local`:

```bash
printf 'NEXT_PUBLIC_BACKEND_ORIGIN=http://localhost:8000\nNEXT_PUBLIC_WEBAUTHN_RP_ID=localhost\n' > frontend/.env.local
```

Without `NEXT_PUBLIC_BACKEND_ORIGIN` the dashboard renders nothing: each panel
reports that no backend is configured. There is no fixture fallback, on
purpose. Sample data rendered in the same panels, with the same styling, as a
real blocked attack is indistinguishable from the real thing on screen, which
is the exact unearned trust this project exists to argue against.

---

## Running (single machine)

### Quick start

```bash
./start.sh
```

Does everything above in one command: checks prerequisites, creates `.env` and
`frontend/.env.local` if they are missing, installs backend and npm
dependencies, builds the SDK, then starts the backend and the dashboard in the
right order and waits until each is actually answering before reporting it up.
Ctrl+C stops both and releases the ports.

```bash
./start.sh --backend-only     # no dashboard
./start.sh --skip-install     # skip dependency install/build
BACKEND_PORT=8010 FRONTEND_PORT=3010 ./start.sh
```

It refuses to start on a port that is already in use rather than half-starting,
tells you whether Chronicle will narrate live or fall back, and writes server
output to `.run/backend.log` and `.run/frontend.log`.

> If you change `FRONTEND_PORT`, update `WEBAUTHN_RP_ORIGIN` in `.env` to match
> — the passkey demo at `/demo` checks the origin and will otherwise reject it.

### Manual start

Start order matters: **backend → sdk build → frontend**.

```bash
# terminal 1 — gateway, Radar, Guardian, Chronicle, SSE stream
python -m uvicorn backend.main:app --port 8000 --reload

# terminal 2 — dashboard and browser demo
cd frontend && npm run dev
```

| URL | What it is |
|---|---|
| http://localhost:3000 | Dashboard — Radar, live event feed, incident timeline, Chronicle, Guardian |
| http://localhost:3000/demo | Browser demo — passkey registration, login, signed request, the no-proof attack |
| http://localhost:8000/health | Liveness probe (`{"status":"ok"}`) |
| http://localhost:8000/docs | Backend OpenAPI |
| http://localhost:8000/events/stream | Raw SSE event stream |

All rendered times in the dashboard and the attacker console are shown in
**IST** (`Asia/Kolkata`). Timestamps on the wire stay UTC ISO-8601 — the
contracts and PulseLock's freshness check are unchanged; only the display
layer is localized.

---

## Demo script (single machine)

Run these in order with the dashboard open in a second window — every step
writes a `SecurityEvent` that appears live on the feed.

**1 · The vulnerability is real** (attacker console, terminal 3)

```bash
python -m backend.attacker_console.replay
```

Five scenes against the running gateway: a stolen cookie replayed in baseline
mode **succeeds** (the required negative control — if this ever fails, the demo
proves nothing), the identical replay in protected mode is **blocked** as
`proof_absent`, the victim's own signed request still works, a captured signed
request replayed verbatim is blocked as `nonce_reused`, and a tampered body is
blocked as `body_hash_mismatch`.

**2 · The browser half** — open http://localhost:3000/demo

The page walks five buttons:

1. **Register passkey** — WebAuthn ceremony, session bound to a fresh key
2. **Log in** — passkey assertion; a session cookie is issued
3. **Signed transfer** — a PulseLock-signed request; accepted
4. **Same request, no proof** — the stolen-cookie request with no signature.
   Before PulseLock it is **accepted**; that is the vulnerability
5. **Enable PulseLock** — now re-run step 4 and the identical request is
   **refused** as `proof_absent`

Watch the indicator flip to **Protected** and each step land on the dashboard
feed.

**3 · Guardian policy** — the "Simulated apps" control on the dashboard, or:

```bash
python -m backend.attacker_console.oauth_consent
```

A consent-phishing OAuth request is blocked with the failing condition named
(e.g. `unverified_publisher_with_high_risk_scope`); a clean one is allowed.
Device-code is deny-by-default and only allowed when every FR-9 condition holds
(allowlisted app, registered device, short-lived code).

**4 · Chronicle** — select an incident on the dashboard timeline and ask for an
explanation. It is grounded strictly in the referenced events; anything it
cannot support from those fields it declines to state. With no `GROQ_API_KEY`
it uses the deterministic fallback and says so.

---

## The two-laptop LAN demo

The headline demo runs a real AiTM path: a victim laptop reaches the app only
through an attacker-controlled TLS proxy, and everything the victim's browser
sends is skimmed off the wire. The full choreography, cert trust, and hosts
setup live in [`KAAVAL_Demo_LAN_Reengineering.md`](KAAVAL_Demo_LAN_Reengineering.md)
and [`demo-tools/README.md`](demo-tools/README.md); the short version:

**Laptop B (attacker / host / projector)**

```bash
# 1. one-time: trust and generate the cert for kaaval.demo
mkcert -install && mkcert kaaval.demo
mv kaaval.demo*.pem demo-tools/attacker/certs/

# 2. bring up the core stack (backend → frontend), built against the demo origin
./start-demo.sh                       # DEMO_HOST=kaaval.demo, proxy port 443

# 3. bring up ONLY the TLS proxy + the attacker web console
bash demo-tools/attacker/run-attacker.sh
```

`start-demo.sh` builds the frontend against `https://kaaval.demo` (not
localhost) and runs `next start`, not `next dev` — dev-mode HMR opens a
WebSocket back through the proxy that reliably fails on the LAN path and can
leave the page looking hydrated with dead buttons. The attacker web console is
served on `http://localhost:8080` on Laptop B; it is the browser-driven
equivalent of the `replay-cookie.js` / `tamper-request.js` CLI scripts, driving
the same skimmed capture files. Its redesigned UI lives in
[`demo-tools/attacker/hacker-page.html`](demo-tools/attacker/hacker-page.html).

**Laptop A (victim)**

```bash
bash demo-tools/victim-setup/run-victim-setup.sh
```

Runs the pre-flight checks — `kaaval.demo` points at Laptop B's current LAN IP,
and the mkcert CA is trusted so the padlock is clean — and only then launches
Chrome at `https://kaaval.demo/demo`. It **stops loudly** on any failure rather
than launching into a half-broken demo.

Then the story is the same as the single-machine script, except the attacks are
fired from the attacker console on Laptop B and land live on the victim's
dashboard: skim the cookie, replay it (baseline works, protected is blocked),
tamper a signed request (`body_hash_mismatch`), replay one verbatim
(`nonce_reused`).

Stopping: `./stop-demo.sh` kills whatever is bound to the demo ports (proxy,
backend, frontend) as a fallback when the Ctrl+C traps didn't run.

---

## API surface

All under the backend origin (`http://localhost:8000`).

| Method | Path | Module | Purpose |
|---|---|---|---|
| GET | `/health` | main | Liveness |
| GET | `/events/stream` | gateway | SSE stream of `SecurityEvent`s |
| POST | `/auth/webauthn/register/begin` · `/finish` | gateway | Passkey registration ceremony |
| POST | `/auth/webauthn/login/begin` · `/finish` | gateway | Passkey login ceremony |
| POST | `/auth/nonce` | gateway | Issue a single-use nonce |
| POST | `/api/transfer` | demo-app | Protected demo action (signature verified) |
| GET/POST | `/api/protection` · `/enable` · `/disable` | demo-app | Per-session PulseLock enrollment |
| GET | `/radar/report` | radar | Exposure report for the simulated org |
| POST | `/radar/estimate` | radar | Score operator-supplied counts |
| POST | `/guardian/oauth/evaluate` | guardian | Allow/block an OAuth consent grant |
| POST | `/guardian/device-code/evaluate` | guardian | Allow/block a device-code request (deny-by-default) |
| POST | `/chronicle/explain` | chronicle | Grounded narration of selected events |

CORS is restricted to the dashboard origins in `DASHBOARD_ORIGINS`.

---

## Tests

```bash
python -m pytest backend/ -q                   # backend, incl. cross-module smoke test
cd sdk && npm test && npm run typecheck        # SDK
cd frontend && npm run build && npm run lint   # dashboard
```

There is also a live wire-contract check that runs the **compiled SDK against
a running gateway** with a real ECDSA P-256 authenticator. It needs the
backend up on port 8500:

```bash
WEBAUTHN_RP_ID=localhost WEBAUTHN_RP_ORIGIN=http://localhost:3000 \
  python -m uvicorn backend.main:app --port 8500
cd sdk && npm run live-check
```

The backend suite covers verification (all seven checks and their failure
reasons), nonce single-use and expiry, the WebAuthn routes, the demo app's
baseline-vs-protected behavior, the SSE stream, Radar scoring, both Guardian
policies, and Chronicle's prompt, fallback, remediation, and faithfulness
checks — plus `test_integration_smoke.py`, which exercises a full signed
request end to end across modules.

---

## Layout

```text
backend/
  contracts.py            frozen data models — the single source of truth (TRD §6)
  main.py                 the one FastAPI app; mounts every router
  db.py  events.py        shared SQLite connection and the one event bus
  gateway/                WebAuthn, nonces, seven-step verify, demo app, SSE stream
  radar/                  deterministic checklist scoring over a simulated org
  guardian/               deterministic OAuth-consent + device-code policy
  chronicle/              grounded incident narration (Groq, with a fallback)
  attacker_console/       simulated attacks — demo tools, clearly labelled
sdk/
  src/                    keys, WebAuthn, canonical string, signing client, indicator
  dist/                   compiled output the frontend imports
  mock-server/            a standalone gateway stub for SDK tests
frontend/
  app/                    Next.js dashboard (page.tsx) + /demo page
  app/components/         Radar, live feed, timeline, Chronicle, Guardian panels
  lib/                    contracts, event client, incident selection, IST display
demo-tools/
  attacker/               TLS proxy, web console, replay/tamper scripts, certs
  victim-setup/           hosts + cert-trust pre-flight and browser launch
start.sh                  one-command single-machine stack
start-demo.sh             two-laptop LAN core stack (Laptop B)
stop-demo.sh              kill whatever holds the demo ports
```

Design documents: [`KAAVAL_PRD.md`](KAAVAL_PRD.md),
[`KAAVAL_TRD.md`](KAAVAL_TRD.md),
[`KAAVAL_Team_Integration_Plan.md`](KAAVAL_Team_Integration_Plan.md),
[`KAAVAL_Demo_LAN_Reengineering.md`](KAAVAL_Demo_LAN_Reengineering.md), and each
module's build document (`KAAVAL_Build_*.md`).
