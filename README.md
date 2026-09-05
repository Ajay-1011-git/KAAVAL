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

The reference deployment runs in **one FastAPI process over one SQLite
database** with an in-process event bus — that is a deliberate choice for the
demo footprint, not a ceiling on what the architecture supports. Every piece
of state the gateway touches (sessions, nonces, sequences, the event log) is
addressed by a single key — `session_id` — which is exactly the shape of state
that shards and replicates without redesign. Two design lines are load-bearing
and stated in the PRD:

- **No opaque scores stand in for proof.** Every Radar finding and every
  Guardian block names its exact source check (PRD NFR-2). No ML risk model,
  no `confidence: 0.73` anywhere.
- **No behavioral biometrics or fingerprinting** (PRD §4.2). Supporting
  signals (new device, new country) may inform investigation or trigger
  step-up auth; they are never treated as identity.

See [Path to scale](#path-to-scale) below for what a production deployment
would actually require.

Working across more than one module? Read
[`KAAVAL_Team_Integration_Plan.md`](KAAVAL_Team_Integration_Plan.md) first —
it defines module ownership, the frozen contracts, and the merge order.

---

## Status

Verified against the code and the test suite in this repo — `python -m pytest
backend/ -q` reports **138 passed** and `cd sdk && npm test` reports **24
passed**.

**Works end to end today:**

- **PulseLock, full path.** Real WebAuthn register/login via `py_webauthn`; a
  non-exportable ECDSA P-256 session key generated in the browser
  (`sdk/src/keys.ts`, `extractable: false`); per-request canonical-string
  signing in the SDK; the gateway's seven ordered checks in
  [`backend/gateway/verify.py`](backend/gateway/verify.py) — session active,
  signature, method/origin/path, body-hash, single-use nonce,
  strictly-increasing sequence, freshness window. Each rejection names the
  check that failed and writes a `SecurityEvent`.
- **The before/after is decided by the server, not the caller.** A stolen
  cookie replayed against a session that has not enrolled PulseLock succeeds;
  the identical request after enrollment is refused as `proof_absent`. The
  demo client cannot pick its own mode.
- **Two attacker consoles** send real HTTP to the real gateway: a 5-scene
  Python script (`python -m backend.attacker_console.replay`) and an 8-step
  browser console (`demo-tools/attacker/`) that also exercises origin
  mismatch, a freshly forged key, and post-revocation replay.
- **Radar** scores a fixed, clearly-simulated 100-account org against nine
  named checks with a documented weight formula
  ([`backend/radar/scoring.py`](backend/radar/scoring.py)), and also scores
  operator-supplied counts (`POST /radar/estimate`). Every finding names one
  check; no ML, no confidence number.
- **Guardian** evaluates OAuth-consent and device-code requests with pure
  if/else policy; device-code is deny-by-default; every block returns the name
  of the failing condition.
- **Chronicle** narrates a selected set of events. With `GROQ_API_KEY` set it
  makes one non-retried Groq call (5s timeout, `temperature=0`, JSON mode);
  with the key blank, `CHRONICLE_FALLBACK_MODE=true`, or on any failure or
  ungrounded response it uses [`backend/chronicle/fallback.py`](backend/chronicle/fallback.py).
  Remediation text is always a deterministic `reason`-keyed lookup, never
  model-authored, and a faithfulness check flags any entity in the summary
  absent from the source events.
- **Dashboard** (Next.js) renders Radar, a live SSE feed, an incident
  timeline, Chronicle, and Guardian triggers. With no backend configured the
  panels render empty — there is no fixture fallback, deliberately.

**Partial or deliberately deferred:**

- **Single process, single SQLite file, in-process SSE** — the event stream is
  a 0.5s `rowid > cursor` poll, not pub/sub. Fine for the demo; see
  [Path to scale](#path-to-scale).
- **Contract enforcement is uneven.** Radar returns its Pydantic `RadarReport`
  model directly; Chronicle and Guardian return the same contract *shapes* as
  hand-built JSON. `IncidentExplanation` is defined in `contracts.py` but not
  enforced at Chronicle's endpoint.
- **`KAAVAL_DEFAULT_MODE` is inert** — still documented, but the code no longer
  reads it; per-session enrollment drives the demo path.
- **The query string is outside the signature.** The canonical string covers
  `path` but not `?query` — a documented limitation of the frozen envelope, so
  `?mode=` is a server-side/demo affordance only.
- **The two-laptop LAN demo** needs `mkcert` and a manual hosts entry; the
  helper scripts pre-flight it but it is not a one-command path.

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
[`backend/contracts.py`](backend/contracts.py) and are frozen. Radar serves
its `RadarReport` model directly; Chronicle and Guardian return the same
contract shapes as JSON. (`IncidentExplanation` is defined but not yet
enforced at Chronicle's endpoint — see [Status](#status).)

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
| `KAAVAL_DEFAULT_MODE` | `protected` | **Currently inert** — retained as a documented knob but not read. With no `?mode=`, the session's own PulseLock enrollment decides. |
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

## What the attacker console actually tests

The attacker console (`demo-tools/attacker/hacker-page.html`, served by
`demo-tools/attacker/hacker-console.js`) is a browser-driven front end onto a
fixed sequence of real attacks. It holds nothing back and cheats nothing: it
sends exactly the requests a real attacker sitting on the wire could send —
the skimmed session cookie, and, once one has been skimmed, the victim's own
genuinely signed request. It never asks the gateway to run in a particular
mode and it never reads or displays the victim's protection state; whether
each attempt succeeds or fails is decided entirely by the gateway, based only
on the victim's own session — the console just reports what actually came
back.

Each attack request is a normal HTTP call to the real backend
(`backend/gateway/demo_app_routes.py` → `backend/gateway/verify.py`), and every
attempt — allowed or blocked — is recorded as a real `SecurityEvent` and pushed
over SSE to the victim's dashboard, so the audience watches the block happen
live rather than reading a canned result.

**Before the victim's session has PulseLock enabled**, the only material the
attacker holds is a stolen session cookie. The demo application, like most
production apps today, trusts a valid cookie by itself — that is the
industry-standard bearer-token model, not a weakened stand-in for it. Two
tests run against exactly that trust:

1. **Replay the stolen cookie.** The attacker sends the victim's cookie alone,
   no signature, requesting a transfer to an attacker-controlled account. The
   gateway looks up the session, finds it active, and — because PulseLock is
   not yet enrolled for it — executes the transfer. The money moves. This is
   the state of a cookie-based session today, passkey login or not: AiTM
   defeats even strong authentication because the theft happens *after* login,
   against a credential nobody re-checks per request.
2. **Repeat the same replay.** The identical cookie, sent again. It succeeds
   again, as many times as the attacker cares to send it — a bearer credential
   has no notion of "already used."

**The victim then enables PulseLock** for that session and makes one normal,
PulseLock-signed transfer. The proxy, still sitting on the wire, skims that
fully valid, fully signed request. The attacker now holds both the original
cookie and one genuine `X-KAAVAL-Proof` envelope — the strongest material an
AiTM position can produce. Every subsequent test is run against that real,
unmodified signature; nothing about check 2 (`signature_invalid`) is dodged by
substituting a synthetic proof.

3. **Replay the stolen cookie once more.** Same request as before, cookie
   only, no proof. This time the gateway's response is `proof_absent`: a
   cookie by itself no longer authorizes anything. The session it belongs to
   now requires a signature, and there isn't one.
4. **Replay the captured signed request, byte-for-byte.** The full envelope —
   the same signature, the same nonce, the same body — resent unchanged. The
   signature verifies (it is completely genuine), but the single-use nonce it
   carries was already consumed by the victim's own request. The gateway
   rejects it as `nonce_reused` before ever reaching the checks further down
   the chain.
5. **Reuse the real signature, change the transfer amount.** The attacker
   keeps the genuine signature and proof exactly as captured, but rewrites the
   transfer amount in the body before resending. The signature covers a
   SHA-256 hash of the original body, so the recomputed hash of the tampered
   body no longer matches what was signed. Rejected as `body_hash_mismatch` —
   a stolen signature cannot be re-pointed at a different action.
6. **Reuse the real signature from a different origin.** The attacker resends
   the untouched, genuinely signed envelope, but from their own origin instead
   of the one the victim actually signed the request for. The signature is
   still cryptographically valid — origin is not what the signature
   algorithm checks — but the gateway separately compares the envelope's
   asserted origin against the request's actual origin, and they no longer
   agree. Rejected as `request_mismatch`.
7. **Forge a brand-new signature with a freshly generated key.** Having failed
   every attempt to reuse the real signature, the attacker gives up on reuse
   entirely and tries to produce their own: they fetch a genuinely valid,
   unused nonce for the stolen session, compute a correct body hash, use the
   correct origin and path — every field is authentic except one — then sign
   the canonical string with a brand-new ECDSA P-256 key pair generated inside
   the attacker console itself, never the victim's browser. The gateway
   rebuilds the expected signature from the public key it bound to that
   session at login and finds no match. Rejected as `signature_invalid`. This
   is the test that answers "couldn't the attacker just sign it themselves?"
   directly: yes, they can produce a perfectly well-formed signature — it is
   simply not verifiable against the key the session was ever bound to.
8. **Replay the captured request once more, after the victim reacts.** The
   victim ends the session with a single action (`POST
   /auth/session/revoke`), which flips the session's active flag off in the
   database. The attacker resends the same genuinely signed envelope from
   step 4. Check 1 of the seven-step order (`session_inactive`) runs before
   the signature is ever verified, so even a perfectly valid, never-reused
   signature is refused outright the instant the victim revokes the session
   it belongs to.

Every one of these eight tests exercises a distinct, named failure reason in
`backend/gateway/verify.py`'s seven ordered checks
(`session_inactive`, `signature_invalid`, `request_mismatch`,
`body_hash_mismatch`, `nonce_reused`, `sequence_invalid`, `timestamp_stale`) or
the upstream `proof_absent` case for a missing envelope. None of the blocks is
a heuristic, a score, or a guess at attacker intent — each one is a specific,
reproducible cryptographic or bookkeeping fact about the request that failed
to hold, logged as a `SecurityEvent` naming exactly which check failed and why.

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
the same skimmed capture files. Its UI lives in
[`demo-tools/attacker/hacker-page.html`](demo-tools/attacker/hacker-page.html)
and runs the fixed, eight-test sequence described in
[What the attacker console actually tests](#what-the-attacker-console-actually-tests)
above.

**Laptop A (victim)**

```bash
bash demo-tools/victim-setup/run-victim-setup.sh
```

Runs the pre-flight checks — `kaaval.demo` points at Laptop B's current LAN IP,
and the mkcert CA is trusted so the padlock is clean — and only then launches
Chrome at `https://kaaval.demo/demo`. It **stops loudly** on any failure rather
than launching into a half-broken demo.

Then the story is the same eight-test sequence as the single-machine script,
except the attacks are fired from the attacker console on Laptop B against
traffic genuinely skimmed off the wire, and land live on the victim's
dashboard — the AiTM position is real, not simulated locally.

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
| POST | `/auth/session/revoke` | gateway | End the current session server-side (flips `is_active`; exercises check 1) |
| POST | `/api/transfer` | demo-app | Protected demo action (signature verified) |
| GET/POST | `/api/protection` · `/enable` · `/disable` | demo-app | Per-session PulseLock enrollment |
| GET | `/radar/report?org_id=` | radar | Exposure report for the simulated org (`org_id` required) |
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

## Why this is different

The attack KAAVAL targets is a *post-authentication* one: an
adversary-in-the-middle reverse proxy relays your whole login — passkey
ceremony included — then skims the session cookie the site hands back. That
cookie is a bearer credential, so replaying it is enough. PulseLock makes the
session unusable without a fresh per-request signature from a key the proxy
never sees. Where that sits relative to the other proof-of-possession
approaches:

| Property | Cookie session | Token Binding (RFC 8471) | OAuth DPoP (RFC 9449) | KAAVAL PulseLock |
|---|---|---|---|---|
| Per-request proof of possession | none (bearer) | per TLS connection | yes — signed JWT proof header | yes — signed envelope over a fixed canonical string ([`verify.py`](backend/gateway/verify.py)) |
| Key location | n/a | TLS stack | app-held, usually non-exportable | non-exportable ECDSA P-256 in Web Crypto (`keys.ts`, `extractable: false`) |
| Captured request replayed verbatim | succeeds | n/a | blocked only if the server issues a nonce | blocked — single-use server nonce (`nonce_reused`) **and** strictly-increasing per-session sequence (`sequence_invalid`) |
| Stolen signature re-pointed at a new body / method / path | n/a | not covered | method + URL covered; body not signed | method, origin, path **and** SHA-256 body hash are all inside the signed string (`request_mismatch`, `body_hash_mismatch`) |
| Request origin bound | no | connection-bound | not standard | asserted origin must equal the `Origin` header and is inside the signature |
| Freshness bound | cookie lifetime | connection lifetime | `iat` window | ±`REQUEST_FRESHNESS_WINDOW_SECONDS` (30s default), `timestamp_stale` |
| Identity tied in at bind time | separate step | separate | separate | the WebAuthn passkey login binds the session public key in the same ceremony |
| Browser support today | universal | withdrawn from major browsers | works via `fetch`, needs app code | Web Crypto + WebAuthn, current browsers |

> The Token Binding and DPoP columns describe those specs as published (RFC
> 8471–8473; RFC 9449) — worth a second read against the RFCs before quoting
> them to a judge. The KAAVAL column is all traceable to
> [`backend/gateway/verify.py`](backend/gateway/verify.py) and
> [`sdk/src/canonical.ts`](sdk/src/canonical.ts). Known gap: the canonical
> string covers `path` but not the query string.

---

## Market & business model

**Who would pay.** The failure PulseLock closes is a stolen session cookie
being replayed from somewhere else after a legitimate (even passkey) login —
the Evilginx / AiTM class that MFA rollouts do not stop. That maps to buyers
who have already deployed strong auth and know it is not sufficient: SaaS
vendors protecting tenant-admin sessions, fintech and payments flows (the demo
action is literally a funds transfer), healthcare and internal admin portals,
and MSSP / MDR practices that would run Radar + Guardian + Chronicle as a
recurring exposure-assessment and incident-narration service.

**Open-core split — matched to separable code:**

- *Free, self-hosted:* the entire gateway (`backend/gateway/`), the browser
  SDK (`sdk/`), Radar, Guardian, the deterministic Chronicle narrator, and the
  dashboard. This is a complete, runnable system with **no paid dependency** —
  `GROQ_API_KEY` blank still produces narrated incidents.
- *Paid / hosted tier* — only things that are genuinely isolated in the code
  today:
  - **Managed LLM narration.** Chronicle's Groq call sits entirely behind
    `_live_configuration()` in [`chronicle/routes.py`](backend/chronicle/routes.py)
    and is optional; a hosted tier bundles the key, model selection, and
    prompt upkeep.
  - **Directory integration.** Radar currently scores one fixed simulated org
    or operator-typed counts (`/radar/estimate`). Auto-populating those counts
    from Entra ID / Okta / Google Workspace is not built and is a natural
    paid add-on.
  - **Event retention and fan-out.** The event log is a local SQLite table
    read by an in-process poll; retention, SIEM/SOC export, and multi-region
    dashboards are hosted-tier features.
  - **Support and SLAs.**

**Cost structure (from `requirements.txt`, `package.json`, and the code).**
The only usage-metered external dependency anywhere in the system is Groq, and
only for Chronicle: one non-retried request per incident explanation,
`temperature=0`, JSON mode, roughly 150 completion tokens, 5-second timeout. If
the key is unset or the call fails, the deterministic path runs at zero
marginal cost. Everything else — FastAPI, Uvicorn, Pydantic, `cryptography`,
`py_webauthn`, `sse-starlette`, Next.js, React, Tailwind — is free and
open-source. No database licence, no cloud service, no per-seat identity-vendor
fee: the reference deployment is one process against one file.

---

## Who this helps

Framed as what the architecture enables, not as anything that has been
deployed:

- It runs on one machine, one process, one SQLite file, and `./start.sh` is
  the whole setup. A small team can stand up per-request session integrity
  without an enterprise identity suite or a cloud contract.
- There is no paid dependency in the default configuration, and the one
  optional external call (LLM narration) degrades to a local deterministic
  narrative — a budget-constrained or air-gapped deployment loses phrasing,
  not security decisions.
- The browser SDK is framework-agnostic TypeScript with **zero runtime
  dependencies**; it uses only Web Crypto and WebAuthn, already in the browser.
- Radar's operator-estimate mode produces an exposure score from a handful of
  numbers an admin can read off their existing identity console — no
  integration work.
- Every security decision is deterministic and names its cause, so a team
  without a dedicated analyst can still act on the output.

The effect is to lower the floor for who can run phishing-resistant session
protection: the cost is a laptop and the time to read this file, not a
six-figure identity platform.

---

## Fiscal feasibility

Backend dependencies (`backend/requirements.txt`) are FastAPI, Uvicorn,
Pydantic, `cryptography`, `py_webauthn`, `sse-starlette`, `python-dotenv`,
`groq`, and `pytest` — all free and open-source under permissive licences. The
frontend (`frontend/package.json`) is Next.js, React, and Tailwind CSS plus
the path-linked local SDK; the SDK itself (`sdk/package.json`) carries only dev
dependencies (TypeScript, Vitest, jsdom). The single paid dependency is the
Groq API, used only by Chronicle for live narration, and the code degrades to
[`backend/chronicle/fallback.py`](backend/chronicle/fallback.py) whenever the
key is unset, the model is unavailable, the call times out, or the response
fails validation — exercised by `backend/chronicle/test_routes.py`
(`test_no_key_means_the_deterministic_fallback`, `test_timeout_uses_fallback`,
`test_malformed_live_output_uses_fallback`). The system has a real zero-cost
operating mode, not a theoretical one.

---

## Path to scale

Today every piece of state lives in one SQLite file, opened per call via
`get_connection()` in [`backend/db.py`](backend/db.py): `sessions` and
`events` (schema in `db.py`), `nonces` ([`gateway/nonce.py`](backend/gateway/nonce.py)),
the WebAuthn tables ([`gateway/webauthn_routes.py`](backend/gateway/webauthn_routes.py)),
and the demo-app tables ([`gateway/demo_app_routes.py`](backend/gateway/demo_app_routes.py)).
The event stream in [`backend/events.py`](backend/events.py) /
[`gateway/events_stream.py`](backend/gateway/events_stream.py) is **not**
pub/sub — each connected dashboard polls `rowid > cursor` every 0.5 seconds on
its own connection. That is deliberate for a laptop demo and is the main
distance between here and production. The verification path itself is already
stateless per request — `verify_request()` reads one `sessions` row and one
`nonces` row, both keyed by `session_id`, with no shared in-process cache — so
running several gateway instances behind a load balancer is a small step. The
larger work is storage: there is no database abstraction, so SQLite-specific
SQL (`rowid`, `INSERT OR IGNORE`, `executescript`, positional `?` params) and
`sqlite3.connect` appear directly in roughly eight files. Moving to a networked
store (Postgres, or a distributed SQL engine) means introducing that
abstraction and porting those queries — mechanical but real — after which
`sessions` and `nonces` shard cleanly on `session_id`. Replacing the SSE poll
with a broker or Postgres `LISTEN`/`NOTIFY` is the other required change. Radar
and Guardian are already pure functions with no persistence; Chronicle already
has a bounded external call with a local fallback.

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
