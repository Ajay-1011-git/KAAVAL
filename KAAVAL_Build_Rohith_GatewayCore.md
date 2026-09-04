# GATEWAY CORE — Complete Build Instructions
### Drift-proof, hallucination-resistant prompts aligned to KAAVAL_PRD.md and KAAVAL_TRD.md

> **Purpose.** Build the server half of PulseLock — session-to-key binding, nonce issuance, signature verification, replay prevention — plus the protected demo application and the attacker/replay console that makes the before/after demonstrable live. This is also the module that performs Stage 0 (shared scaffold) before anyone else branches.
>
> **Alignment guarantee.** If anything here conflicts with `KAAVAL_PRD.md` or `KAAVAL_TRD.md`, those documents win.
>
> **Partner module note.** Ajay's `feature/browser-sdk` is the client this gateway verifies requests from. Adhi's `feature/radar-guardian` writes to the same `events` table you own the schema for, and Sai's `feature/dashboard-chronicle` reads from it via the `/events/stream` endpoint you host. You do not need any of their real code to finish or verify your own tasks — the contracts in §B.2 are enough. Do not touch `sdk/`, `frontend/`, `backend/radar/`, `backend/guardian/`, or `backend/chronicle/`.

---

# §A. Operating Contract — paste into CLAUDE.md

**What this module is.** The FastAPI backend's `gateway/` router: binds authenticated sessions to a browser-generated public key, issues single-use nonces, verifies the signature on every protected request, rejects replays, and hosts a demo application with a baseline (unprotected) mode and a PulseLock-protected mode so the vulnerability and the fix are both demonstrable. You also own the shared `events` table schema and the `/events/stream` SSE endpoint, and you perform Stage 0 of the Team Integration Plan.

**GROUND TRUTH — do not silently change:**
- Stack: FastAPI, SQLite for the MVP, Web Crypto-compatible ECDSA P-256 signature verification server-side.
- The canonical string format and verification order are fixed exactly as TRD §6.1 states — the seven checks, in that order, every one required.
- You own `backend/gateway/`, `backend/main.py`, `backend/events.py`, `backend/contracts.py` (created once in Stage 0, then frozen — see the Team Integration Plan §2 on who may edit it after that).
- No Redis, no distributed infrastructure — SQLite and in-process state only, per PRD §4.2 and TRD's stack justification, unless the team explicitly agrees load requires otherwise.
- Supporting signals (new device, new country, impossible travel, etc.) may only ever inform investigation or trigger step-up auth — never treat them as proof of identity (PRD NFR-1). Do not add a risk score that silently substitutes for cryptographic proof.

**ANTI-HALLUCINATION RULES:**
1. Never invent the exact API of whatever WebAuthn server library you choose (e.g. `py_webauthn`). Verify its real, current API (search its actual PyPI page/docs or GitHub README in this session) before writing code against it — do not assume method names or return shapes from memory.
2. Never assume the exact parameter shape for server-side ECDSA P-256 signature verification in your chosen crypto library (e.g. `cryptography` in Python) — verify current usage in-session before writing it.
3. Import all contract types from `backend/contracts.py` — never redefine `SecurityEvent` or `SignedRequestEnvelope` a second time anywhere else in the backend.
4. If a requirement is ambiguous, ask one clarifying question rather than assuming.
5. Never fabricate command output — run real commands and paste real output, including for the negative-control (baseline replay succeeds) test.

**ANTI-DRIFT RULES:**
- Only touch files listed in a task's "Files you may touch."
- Don't refactor Adhi's or Sai's modules, even if you notice something you'd do differently — flag it instead.
- Keep `backend/contracts.py` byte-identical to TRD §6 after Stage 0; any change requires a synchronous team decision and an amendment, not a silent edit.

**QUALITY GATES:** type safety (Pydantic models from `contracts.py` used everywhere, no ad hoc dicts crossing a module boundary), validation at every external-data boundary (a malformed `X-KAAVAL-Proof` header is a rejection, not a 500 error), idempotent nonce/sequence checks, structured error responses (never a bare 500 for an expected failure mode), no secrets in code.

**WORKING METHOD:** short plan first for multi-file tasks (wait for confirmation), implement, run real VERIFY commands and paste real output, extend tests, commit as `T-RO.<n>: <short description>`.

**DEFINITION OF DONE:** runs cleanly, typechecks/lints clean, VERIFY passes with real pasted output, `contracts.py` unchanged from TRD §6 after Stage 0, only permitted files touched.

---

# §B. Canonical Specifications

## B.1 Environment variables

```text
DATABASE_URL=sqlite:///./kaaval.db
WEBAUTHN_RP_ID=kaaval-demo.local          # must match Ajay's SDK config exactly
WEBAUTHN_RP_ORIGIN=https://kaaval-demo.local
NONCE_TTL_SECONDS=30                      # single-use nonce validity window
REQUEST_FRESHNESS_WINDOW_SECONDS=30       # timestamp check window (TRD §6.1 step 7)
```

## B.2 Data contracts (copied verbatim from TRD §6.1 and §6.2 — this is the file you create in Stage 0 and freeze)

```python
# backend/contracts.py
from pydantic import BaseModel
from typing import Optional, Literal

class SignedRequestEnvelope(BaseModel):
    session_id: str
    method: str
    origin: str
    path: str
    body_hash: str
    nonce: str
    sequence: int
    timestamp: str
    signature: str

class SecurityEvent(BaseModel):
    event_id: str
    timestamp: str
    event_type: Literal[
        "session_bound", "replay_attempted", "proof_absent",
        "signature_invalid", "request_blocked", "request_allowed",
        "oauth_grant_blocked", "oauth_grant_allowed", "device_code_blocked",
    ]
    session_id: Optional[str]
    user_id: Optional[str]
    application_id: Optional[str]
    reason: str
    detail: dict
    severity: Literal["info", "warning", "blocked"]
```

Canonical string (fixed order, newline-joined):
```text
session_id\nmethod\norigin\npath\nbody_hash\nnonce\nsequence\ntimestamp
```

Verification order — every check required, first failure wins and is the logged `reason`:
1. Session active → else `reason="session_inactive"`
2. Signature valid against bound public key → else `reason="signature_invalid"`
3. Asserted method/origin/path match actual request → else `reason="request_mismatch"`
4. Asserted body_hash matches SHA-256 of actual received body → else `reason="body_hash_mismatch"`
5. Nonce issued by server and unused → else `reason="nonce_reused"`
6. Sequence valid (> last accepted for session) → else `reason="sequence_invalid"`
7. Timestamp within freshness window → else `reason="timestamp_stale"`

## B.3 File/folder structure

```text
backend/
  main.py                  # Stage 0 — app wiring, routers mounted
  contracts.py              # Stage 0 — frozen, see B.2
  events.py                 # Stage 0 — write_event(SecurityEvent) helper, shared by gateway + guardian
  db.py                      # Stage 0 — SQLite connection + schema migration
  gateway/
    webauthn_routes.py        # T-RO.2, T-RO.3
    nonce.py                   # T-RO.4
    verify.py                   # T-RO.5 — the core verification logic
    demo_app_routes.py           # T-RO.6 — baseline + protected demo endpoints
    events_stream.py              # T-RO.7 — SSE endpoint
  attacker_console/
    replay.py                      # T-RO.8 — standalone cookie-capture/replay simulation tool
```

---

# §C. Tasks

## T-RO.1 · Stage 0 shared scaffold — `backend/main.py`, `backend/contracts.py`, `backend/db.py`, root `.env.example`, root `CLAUDE.md`, root `AGENTS.md` · P0 · depends: none

> **PROMPT**
> Goal: create the repo skeleton described in the Team Integration Plan §3, so all four branches have something real to start from.
> Files you may touch: `backend/main.py`, `backend/contracts.py`, `backend/db.py`, `backend/events.py` (empty stub), `.env.example`, `CLAUDE.md`, `AGENTS.md`, empty router stubs for `radar/`, `guardian/`, `chronicle/`, `frontend/` app shell (via `npx create-next-app` or equivalent — verify the current real command for your chosen Next.js version in-session before running it), `sdk/` package skeleton.
> Requirements: `contracts.py` matches §B.2 exactly. SQLite schema creates `events` and `sessions` tables. `CLAUDE.md` and `AGENTS.md` both open with the identical shared block described in the Team Integration Plan §5 before any module-specific content.
> **VERIFY:** `uvicorn backend.main:app` starts with no errors; `GET /events/stream` returns an empty SSE stream (paste real curl output); `sqlite3 kaaval.db ".tables"` shows `events` and `sessions` (paste real output).

## T-RO.2 · WebAuthn registration endpoint — `backend/gateway/webauthn_routes.py` · P0 · depends: T-RO.1

> **PROMPT**
> Goal: implement `/auth/webauthn/register/begin` and `/finish`, storing the credential public key and the submitted session public key.
> Files you may touch: `backend/gateway/webauthn_routes.py`, its test file.
> Requirements: before writing this, search for and confirm the real current API of whatever WebAuthn server library you choose (e.g. `py_webauthn` on PyPI) in this session — do not assume method names or the shape of `generate_registration_options`/`verify_registration_response`-equivalent calls from memory. `finish` must persist both the passkey credential and the new session public key.
> **VERIFY:** integration test simulating a registration ceremony (using the library's own test/mock attestation helpers, verified to actually exist before use) completes and both keys are persisted; paste real test output.

## T-RO.3 · WebAuthn login + session binding endpoint — `backend/gateway/webauthn_routes.py` · P0 · depends: T-RO.2

> **PROMPT**
> Goal: implement `/auth/webauthn/login/begin` and `/finish`, binding the resulting session to the submitted public key and writing a `session_bound` `SecurityEvent`.
> Files you may touch: `backend/gateway/webauthn_routes.py`, its test file, `backend/events.py` (only to call the existing `write_event` helper, not to redefine it).
> Requirements: same anti-hallucination note as T-RO.2 applies to the login/assertion side. On success, create a session row bound to the public key and call `write_event(SecurityEvent(event_type="session_bound", ...))`.
> **VERIFY:** test showing a login ceremony completes, returns a `session_id`, and a `session_bound` event appears in the `events` table; paste real output.

## T-RO.4 · Nonce issuance — `backend/gateway/nonce.py` · P0 · depends: T-RO.1

> **PROMPT**
> Goal: implement `POST /auth/nonce`, issuing a single-use, short-lived (per `NONCE_TTL_SECONDS`) nonce tied to the requesting session.
> Files you may touch: `backend/gateway/nonce.py`, its test file.
> Requirements: nonce is a cryptographically random value (verify the correct Python `secrets` module usage in-session, don't hand-roll randomness), stored with an expiry and an "unused" flag, marked used the moment it's consumed by a verified request (T-RO.5), never reusable even if verification later fails for another reason.
> **VERIFY:** test showing a nonce is issued, is accepted once, and is rejected on a second use; paste real output.

## T-RO.5 · Signature verification and replay prevention — `backend/gateway/verify.py` · P0 · depends: T-RO.3, T-RO.4

> **PROMPT**
> Goal: implement the full seven-step verification order from §B.2, exactly, as the single function every protected route calls.
> Files you may touch: `backend/gateway/verify.py`, its test file.
> Requirements: implement `verify_request(envelope: SignedRequestEnvelope, actual_request) -> VerifyResult` performing checks 1-7 from §B.2 in order, short-circuiting on first failure, returning which check failed as `reason`. Verify the exact current API for ECDSA P-256 signature verification in your chosen crypto library (e.g. Python's `cryptography` package) in this session before writing the signature-check code — this is the single most safety-critical line in the whole system, do not guess at it. On any failure, call `write_event` with the appropriate `event_type` (`signature_invalid`, `replay_attempted` for a reused nonce, `proof_absent` if the header is missing entirely, `request_blocked` for a mismatch) and the specific `reason`. On success, write `request_allowed`.
> **VERIFY:** this task's test suite is the core of the PRD's success metrics — write and run tests for: (a) a valid envelope passes all seven checks, (b) a missing header is rejected as `proof_absent`, (c) a tampered body is rejected as `body_hash_mismatch`, (d) a reused nonce is rejected as `nonce_reused`/`replay_attempted`, (e) a stale timestamp is rejected as `timestamp_stale`, (f) a signature from an unbound key is rejected as `signature_invalid`. Paste real output for all six, and confirm rejection rate is 100% across a repeated run of (b)-(f) — this is PRD §7's literal success-metric target.

## T-RO.6 · Demo application routes — `backend/gateway/demo_app_routes.py` · P0 · depends: T-RO.5

> **PROMPT**
> Goal: a small demo application (e.g. the `/api/transfer` example from the design docs) with two modes: baseline (accepts a plain session cookie, no signature required) and PulseLock-protected (requires a valid `X-KAAVAL-Proof` via T-RO.5).
> Files you may touch: `backend/gateway/demo_app_routes.py`, its test file.
> Requirements: a mode toggle (query param or config flag, not a security-relevant secret) selects baseline vs. protected behavior for the same underlying action, so the demo can show the identical action succeed insecurely and then fail securely.
> **VERIFY:** test showing the same request succeeds in baseline mode with only a cookie, and is rejected in protected mode without a valid envelope; paste real output.

## T-RO.7 · Events SSE stream — `backend/gateway/events_stream.py` · P0 · depends: T-RO.1

> **PROMPT**
> Goal: `GET /events/stream`, an SSE endpoint emitting new `SecurityEvent` rows as they're written, using a `since_event_id` cursor rather than replaying full history each time (TRD §7).
> Files you may touch: `backend/gateway/events_stream.py`, its test file.
> Requirements: poll or subscribe to new rows in the `events` table (SQLite has no native pub/sub — a short-interval poll against `event_id > cursor` is fine at this scale, don't introduce Redis for this) and emit each as an SSE `data:` message containing the JSON-serialized `SecurityEvent`.
> **VERIFY:** test or curl session showing a newly written event appears on the stream within a bounded delay; paste real output.

## T-RO.8 · Attacker/replay console — `backend/attacker_console/replay.py` · P1 · depends: T-RO.6

> **PROMPT**
> Goal: a small standalone script/tool that captures a session cookie from a baseline-mode login and replays it from a simulated "different browser," for PRD acceptance criteria 1 and 2.
> Files you may touch: `backend/attacker_console/replay.py`.
> Requirements: works against both baseline mode (should succeed — this is a required negative control) and protected mode (should fail with a logged reason). This is a demo tool, not production code — keep it simple and clearly labeled as the attacker simulation.
> **VERIFY:** run it against both modes and paste real output showing baseline replay succeeds and protected replay fails with `signature_invalid` or `proof_absent`.

---

# §D. Build order

| Window | Tasks | Expected outcome |
|---|---|---|
| Day 1, hrs 0-2 | T-RO.1 (Stage 0) | Repo scaffold merged to `main`; everyone else can branch. |
| Day 1, hrs 2-6 | T-RO.2, T-RO.3 | Full WebAuthn registration + login + session binding works. |
| Day 1, hrs 6-8 | T-RO.4 | Nonce issuance and single-use enforcement works. |
| Day 2, hrs 0-4 | T-RO.5 | Full seven-step verification logic passes all six test cases at 100% rejection rate. |
| Day 2, hrs 4-6 | T-RO.6 | Demo app baseline + protected modes both work. |
| Day 2, hrs 6-7 | T-RO.7 | SSE stream live. |
| Day 2, hrs 7-8 | T-RO.8 | Attacker console demonstrates both the vulnerability and the fix. |

---

# §E. Final acceptance

1. ✅ Stage 0 scaffold merged before any other branch started (Team Integration Plan §3-4).
2. ✅ WebAuthn registration and login ceremonies work end-to-end, session bound to public key (T-RO.2, T-RO.3).
3. ✅ Nonces are single-use (T-RO.4).
4. ✅ All six verification test cases in T-RO.5 pass, at 100% rejection rate on the negative cases — this is PRD §7's literal metric.
5. ✅ Baseline mode allows cookie replay; protected mode rejects it — both demonstrated live via T-RO.8, not asserted.
6. ✅ `/events/stream` emits real events with bounded delay (T-RO.7).
7. ✅ `contracts.py` is unchanged from what was frozen in Stage 0.
8. ✅ Only files under `backend/gateway/`, `backend/attacker_console/`, and the Stage 0 scaffold files were touched.
