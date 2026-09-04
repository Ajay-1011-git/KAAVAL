# KAAVAL — shared ground truth

> This shared block is identical in `CLAUDE.md` and `AGENTS.md` (Team Integration Plan §5). Don't overwrite it with only your own module's context — append your module-specific ground truth under your own heading below, and leave this block and the other builders' sections intact.

**Project one-liner:** KAAVAL closes the gap AiTM (Adversary-in-the-Middle) reverse-proxy phishing exploits — a stolen session cookie being a bearer credential nobody re-checks — by binding every authenticated request to a non-exportable, per-session browser key pair and requiring a fresh signature on every request (PulseLock), backed by deterministic exposure scoring (Radar), deterministic authorization policy (Guardian), and post-decision plain-language incident narration (Chronicle).

**GROUND TRUTH — stack (do not silently change):**
- Backend: FastAPI (Python), single process, three routers (`gateway`, `radar`, `guardian`) plus a `chronicle` module, sharing one SQLite database.
- Frontend/dashboard: Next.js + React + Tailwind CSS.
- Browser cryptography: Web Crypto API — non-exportable ECDSA P-256 session key pair, the literal property PulseLock's proof-of-possession model depends on.
- Authentication: WebAuthn / passkeys.
- Live dashboard updates: Server-Sent Events (`GET /events/stream`), one-directional server → dashboard.
- Chronicle's LLM call: Claude API, called only with redacted, structured `SecurityEvent` JSON — never before a security decision already exists, never able to alter one.
- No Redis, no distributed infrastructure — SQLite and in-process state only, unless the whole team agrees load requires otherwise.
- No behavioral biometrics, browser/canvas/font fingerprinting, or network-trust scoring anywhere in the system — deliberately out of scope (PRD §4.2). Supporting signals may inform investigation or trigger step-up auth; they are never proof of identity (PRD NFR-1).

**Module owners (Team Integration Plan §1):**

| Person | Tool | Module | Branch |
|---|---|---|---|
| Ajay | Claude Code Pro | Browser SDK (`sdk/`) | `feature/browser-sdk` |
| Rohith | Claude Code Pro | Gateway core (`backend/gateway/`, `backend/main.py`, `backend/events.py`, `backend/contracts.py`) | `feature/gateway-core` |
| Adhi | Claude Code Pro | Radar + Guardian (`backend/radar/`, `backend/guardian/`) | `feature/radar-guardian` |
| Sai | Codex (ChatGPT Plus) | Dashboard + Chronicle (`frontend/`, `backend/chronicle/`) | `feature/dashboard-chronicle` |

**Source of truth for every schema:** `backend/contracts.py` — `SignedRequestEnvelope` and `SecurityEvent`, copied verbatim from TRD §6.1–§6.2. Frozen after Stage 0; nobody edits it without a synchronous, whole-team decision (Team Integration Plan §2, §7). `RadarReport`/`RadarFinding` live in `backend/radar/models.py`, `IncidentExplanation` in Sai's chronicle module — both also copied verbatim from TRD §6.3–§6.4.

**Nobody edits a file outside their own module's ownership** listed above, with the single exception of this shared block, which the whole team keeps in sync.

---

## Sai — Dashboard + Chronicle

**What this module is.** A Next.js/Tailwind dashboard consuming the live `SecurityEvent` stream, Radar's report, and Guardian's decisions, plus a `chronicle/` backend module that calls an LLM to turn a set of already-decided events into a plain-language incident summary.

**GROUND TRUTH — do not silently change:**
- Chronicle runs strictly after a security decision already exists. It reads `SecurityEvent` rows; it never calls, blocks, allows, or reverses anything in `gateway/`, `radar/`, or `guardian/`. If Chronicle's output is wired back into an enforcement decision, that's a design violation, not a feature.
- Chronicle's LLM call receives only fields already present in the referenced `SecurityEvent` rows — never raw user input, never full session tokens, never anything not already redacted structured data.
- No behavioral biometrics or fingerprinting-based UI signal anywhere on the dashboard — the dashboard displays decisions already made elsewhere, it doesn't introduce a new trust signal of its own.
- Owns `frontend/` and `backend/chronicle/`. Does not modify `backend/contracts.py`.

**ANTI-HALLUCINATION RULES:**
1. Never invent the exact current API surface of the chosen LLM client library (model identifiers, request/response shapes) — verify the real, current API in-session before writing the Chronicle call.
2. Never invent Radar/Guardian/gateway response shapes — they are fixed exactly in TRD §6 and `KAAVAL_Build_Sai_DashboardChronicle.md` §B.2; a mismatch while integrating is a contract violation to flag, not something to silently adapt around.
3. If a requirement is ambiguous, ask one clarifying question rather than assuming.
4. Never fabricate a demo screenshot, test result, or LLM output — run the real thing and paste real output.

**ANTI-DRIFT RULES:**
- Only touch files listed in a task's "Files you may touch."
- Don't add a second, dashboard-local copy of any contract type — import from the fixture/shared definitions.
- Don't let Chronicle's prompt grow to include anything beyond the referenced events' fields.

**QUALITY GATES:** every Chronicle summary is checked against an automated faithfulness rule (every named user, application, and reason must trace back to a referenced event's fields); the dashboard degrades gracefully (a clear "waiting for events" state, not a blank screen) if the SSE stream hasn't sent anything yet; no secrets in code.

**WORKING METHOD:** short plan first for multi-file tasks, implement, run real VERIFY commands and paste real output, commit as `T-SA.<n>: <short description>`.

**DEFINITION OF DONE:** builds cleanly, VERIFY passes with real pasted output (including a real LLM response for Chronicle tasks), `contracts.py` untouched, only permitted files touched.

Full task list and specs: `KAAVAL_Build_Sai_DashboardChronicle.md`.

---

## Ajay — Browser SDK

**What this module is.** A browser SDK (TypeScript, no framework dependency beyond what the demo app already uses) that: generates a non-exportable session key pair via Web Crypto, drives the WebAuthn registration/login ceremonies, canonicalizes and signs every protected request per the `SignedRequestEnvelope` contract, and shows the user a small "protected" state indicator.

**GROUND TRUTH — do not silently change:**
- Stack: TypeScript, Web Crypto API (`window.crypto.subtle`), `navigator.credentials` for WebAuthn. No third-party crypto library — the whole point of PulseLock is a key that never leaves the browser's own secure boundary.
- The canonical string format is fixed: `session_id\nmethod\norigin\npath\nbody_hash\nnonce\nsequence\ntimestamp`, newline-joined, in that exact order. Do not reorder, rename, or add fields.
- You own `sdk/`. Do not touch `backend/`, `frontend/`, or `backend/contracts.py`.
- Behavioral biometrics, browser fingerprinting, and canvas/font fingerprinting are explicitly out of scope (PRD §4.2) — do not add any of these as a "nice to have," even as a secondary signal.

**ANTI-HALLUCINATION RULES:**
1. Never invent the exact shape of `navigator.credentials.create()` / `.get()` options or the WebAuthn attestation/assertion response objects. Verify the real, current WebAuthn browser API in-session (MDN or the spec) before writing code against it.
2. Never assume `window.crypto.subtle.generateKey`/`sign`/`exportKey` parameter shapes from memory without checking current MDN docs for the exact algorithm identifiers (e.g. ECDSA P-256 parameters) you intend to use.
3. Import `SignedRequestEnvelope`'s field names and the canonical string format from §B.2 below — never redefine a second, slightly different version.
4. If a requirement is ambiguous, ask one clarifying question rather than assuming, and state any unavoidable assumption explicitly if you must proceed without an answer.
5. Never fabricate test/console output — run the real thing and paste real output.

**ANTI-DRIFT RULES:**
- Only touch files listed in a task's "Files you may touch."
- Don't refactor unrelated code or add unrequested features (e.g. no "remember me" convenience features that would reintroduce a bearer-style long-lived credential).
- Keep the `SignedRequestEnvelope` shape byte-aligned with §B.2 — field names and types must match exactly, since Rohith's gateway parses this literally.

**QUALITY GATES:**
- The private key never appears in a variable, log, or network payload anywhere — only the public key and signatures do.
- TypeScript strict mode, no `any` on the contract types.
- Every external boundary (WebAuthn response, server response) is validated before use, not assumed well-formed.
- No secrets or relying-party config hardcoded — read from a config object passed into the SDK at init.

**WORKING METHOD:** short plan first for any multi-file task (wait for confirmation), implement, run real VERIFY commands and paste real output, extend tests, commit with message format `T-AJ.<n>: <short description>`.

**DEFINITION OF DONE:** builds cleanly, typechecks with no `any` on contract types, VERIFY passes with real pasted output, the `SignedRequestEnvelope` contract is unchanged from §B.2, only files under `sdk/` were touched.

Full task list and specs: `KAAVAL_Build_Ajay_BrowserSDK.md`. (Canonical copy of this module's Operating Contract lives in `CLAUDE.md`.)

## Rohith — Gateway Core

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

Full task list and specs: `KAAVAL_Build_Rohith_GatewayCore.md`. (Canonical copy of this module's Operating Contract lives in `CLAUDE.md`.)

## Adhi — Radar + Guardian

**What this module is.** Two FastAPI routers, `radar/` and `guardian/`. Radar evaluates a clearly-labeled simulated organization against a fixed checklist and produces an explainable exposure score. Guardian evaluates incoming device-code and OAuth-consent requests against deterministic policy and blocks the ones that fail it.

**GROUND TRUTH — do not silently change:**
- Every finding and every block decision must be explainable — traceable to one named check, never an opaque score (PRD NFR-2). No machine-learning risk model anywhere in this module.
- No probabilistic or LLM-based component may approve, deny, or alter an authorization decision (PRD FR-11) — Guardian's logic is if/else policy, full stop.
- Radar's data is simulated and must be labeled as such everywhere it's surfaced (PRD NFR-5).
- You own `backend/radar/` and `backend/guardian/`. You do not modify `backend/contracts.py` after Stage 0 — import from it.
- Device-code authentication is blocked **by default**; it is only allowed under the specific exception conditions in PRD FR-9 (allowlisted app, registered device, short-lived single-use code, admin approval for sensitive cases) — the default-deny direction is a stated design decision, not something to soften "to be more permissive by default."

**ANTI-HALLUCINATION RULES:**
1. Do not invent real-world OAuth publisher-verification data or a real third-party app registry — the "unverified publisher," "excessive scopes," etc. in the demo are simulated inputs you construct yourself, clearly labeled as such.
2. Import `SecurityEvent` from `backend/contracts.py` — never redefine it.
3. If a requirement is ambiguous, ask one clarifying question rather than assuming.
4. Never fabricate test output — run real commands, paste real output.

**ANTI-DRIFT RULES:**
- Only touch files listed in a task's "Files you may touch."
- Don't add a risk-scoring layer that could be read as a substitute for the deterministic checks — if you're tempted to add "confidence: 0.73" anywhere, stop; that's exactly the pattern this module is designed not to have.

**QUALITY GATES:** every Radar finding names its exact source check; every Guardian block names its exact failing policy condition; all decision logic is pure/deterministic functions, easily unit-testable without any external service.

**WORKING METHOD:** short plan first for multi-file tasks, implement, run real VERIFY commands and paste real output, commit as `T-AD.<n>: <short description>`.

**DEFINITION OF DONE:** runs cleanly, typechecks/lints clean, VERIFY passes with real pasted output, `contracts.py` untouched, only permitted files touched.

Full task list and specs: `KAAVAL_Build_Adhi_RadarGuardian.md`. (Canonical copy of this module's Operating Contract lives in `CLAUDE.md`.)
