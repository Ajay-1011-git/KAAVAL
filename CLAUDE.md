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

## Rohith — Gateway Core

**What this module is.** The FastAPI backend's `gateway/` router: binds authenticated sessions to a browser-generated public key, issues single-use nonces, verifies the signature on every protected request, rejects replays, and hosts a demo application with a baseline (unprotected) mode and a PulseLock-protected mode so the vulnerability and the fix are both demonstrable. Also owns the shared `events` table schema and the `/events/stream` SSE endpoint, and performed Stage 0 of the Team Integration Plan.

**GROUND TRUTH — do not silently change:**
- Stack: FastAPI, SQLite for the MVP, Web Crypto-compatible ECDSA P-256 signature verification server-side.
- The canonical string format and verification order are fixed exactly as TRD §6.1 states — the seven checks, in that order, every one required:
  `session_id\nmethod\norigin\npath\nbody_hash\nnonce\nsequence\ntimestamp`
- Owns `backend/gateway/`, `backend/main.py`, `backend/events.py`, `backend/contracts.py` (created once in Stage 0, then frozen).
- No Redis, no distributed infrastructure — SQLite and in-process state only.
- Supporting signals (new device, new country, impossible travel, etc.) may only ever inform investigation or trigger step-up auth — never treated as proof of identity. No risk score that silently substitutes for cryptographic proof.

**ANTI-HALLUCINATION RULES:**
1. Never invent the exact API of whatever WebAuthn server library is chosen (e.g. `py_webauthn`). Verify its real, current API in-session before writing code against it.
2. Never assume the exact parameter shape for server-side ECDSA P-256 signature verification in the chosen crypto library — verify current usage in-session before writing it.
3. Import all contract types from `backend/contracts.py` — never redefine `SecurityEvent` or `SignedRequestEnvelope` a second time anywhere else in the backend.
4. If a requirement is ambiguous, ask one clarifying question rather than assuming.
5. Never fabricate command output — run real commands and paste real output, including for the negative-control (baseline replay succeeds) test.

**ANTI-DRIFT RULES:**
- Only touch files listed in a task's "Files you may touch."
- Don't refactor Adhi's or Sai's modules, even if something looks off — flag it instead.
- Keep `backend/contracts.py` byte-identical to TRD §6 after Stage 0; any change requires a synchronous team decision and an amendment, not a silent edit.

**QUALITY GATES:** type safety (Pydantic models from `contracts.py` used everywhere, no ad hoc dicts crossing a module boundary), validation at every external-data boundary (a malformed `X-KAAVAL-Proof` header is a rejection, not a 500 error), idempotent nonce/sequence checks, structured error responses, no secrets in code.

**WORKING METHOD:** short plan first for multi-file tasks (wait for confirmation), implement, run real VERIFY commands and paste real output, extend tests, commit as `T-RO.<n>: <short description>`.

**DEFINITION OF DONE:** runs cleanly, typechecks/lints clean, VERIFY passes with real pasted output, `contracts.py` unchanged from TRD §6 after Stage 0, only permitted files touched.

Full task list and specs: `KAAVAL_Build_Rohith_GatewayCore.md`.

---

## Ajay — Browser SDK

Full task list and specs: `KAAVAL_Build_Ajay_BrowserSDK.md`. (Append this module's Operating Contract here when starting that branch.)

---

## Adhi — Radar + Guardian

Full task list and specs: `KAAVAL_Build_Adhi_RadarGuardian.md`. (Append this module's Operating Contract here when starting that branch.)

---

## Sai — Dashboard + Chronicle

Full task list and specs: `KAAVAL_Build_Sai_DashboardChronicle.md`. Codex reads `AGENTS.md`, not this file — the canonical copy of this section lives there.
