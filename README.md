# KAAVAL

Session cookies stolen by an AiTM (Adversary-in-the-Middle) reverse proxy are
bearer credentials that nobody re-checks. KAAVAL binds every authenticated
request to a **non-exportable, per-session browser key pair** and requires a
fresh signature on each one, so a stolen cookie stops being enough.

Four modules, one SQLite database, one event bus:

| Module | Lives in | Does |
|---|---|---|
| **PulseLock — browser SDK** | `sdk/` | Non-exportable session keys, WebAuthn ceremonies, request signing |
| **PulseLock — gateway** | `backend/gateway/` | Session-to-key binding, nonce issuance, seven-step verification, replay prevention, the demo app |
| **Radar** | `backend/radar/` | Deterministic exposure scoring over a simulated org |
| **Guardian** | `backend/guardian/` | Deterministic OAuth-consent and device-code policy |
| **Chronicle + dashboard** | `backend/chronicle/`, `frontend/` | Live event feed, incident timeline, plain-language incident narration |

Working across more than one module? Read
[`KAAVAL_Team_Integration_Plan.md`](KAAVAL_Team_Integration_Plan.md) first —
it defines module ownership, the frozen contracts, and the merge order.

---

## Prerequisites

- **Python 3.11+** (developed on 3.13)
- **Node.js 20+** (developed on 22)
- A browser with **passkey support** for the live demo (Chrome, Edge, or Safari)

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

Chronicle's narration runs on **Groq**. Leave `GROQ_API_KEY` blank and it uses
a deterministic fallback narrative instead of a live call — the demo works
either way, it just stops being LLM-generated.

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
If you'd rather not activate, replace `python` with the venv's own
interpreter path directly: `.venv/bin/python` (macOS/Linux) or
`.venv\Scripts\python` (Windows).

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

Without `NEXT_PUBLIC_BACKEND_ORIGIN` the dashboard renders from local
fixtures instead of the live backend.

---

## Running

### Quick start

```bash
./start.sh
```

Does everything below in one command: checks prerequisites, creates `.env` and
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
| http://localhost:3000 | Dashboard — Radar, live event feed, incident timeline, Chronicle |
| http://localhost:3000/demo | Browser demo — passkey registration, login, signed request |
| http://localhost:8000/docs | Backend OpenAPI |
| http://localhost:8000/events/stream | Raw SSE event stream |

---

## Demo script

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

Register a passkey, log in, watch the indicator flip to **Protected**, then
send a signed transfer. Step 4 on that page sends the same request with no
proof and is rejected.

**3 · Guardian policy** — the buttons on the dashboard, or:

```bash
python -m backend.attacker_console.oauth_consent
```

A consent-phishing OAuth request is blocked with the failing condition named;
a clean one is allowed. Same for device-code, which is deny-by-default.

**4 · Chronicle** — select an incident on the dashboard timeline and ask for an
explanation. It is grounded strictly in the referenced events; anything it
cannot support from those fields it declines to state.

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

---

## Layout

```text
backend/
  contracts.py            frozen data models — the single source of truth (TRD §6)
  db.py  events.py        shared SQLite connection and the one event bus
  gateway/                WebAuthn, nonces, verification, demo app, SSE stream
  radar/  guardian/       deterministic scoring and policy
  chronicle/              grounded incident narration (Groq, with a fallback)
  attacker_console/       simulated attacks — demo tools, clearly labelled
sdk/                      the browser SDK (built to sdk/dist)
frontend/                 Next.js dashboard + /demo page
```

Design documents: [`KAAVAL_PRD.md`](KAAVAL_PRD.md),
[`KAAVAL_TRD.md`](KAAVAL_TRD.md), and each module's build document.
