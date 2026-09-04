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

Full task list and specs: `KAAVAL_Build_Ajay_BrowserSDK.md`. (Canonical copy of this module's Operating Contract lives in `CLAUDE.md`.)

## Rohith — Gateway Core

Full task list and specs: `KAAVAL_Build_Rohith_GatewayCore.md`. (Canonical copy of this module's Operating Contract lives in `CLAUDE.md`.)

## Adhi — Radar + Guardian

Full task list and specs: `KAAVAL_Build_Adhi_RadarGuardian.md`. (Canonical copy of this module's Operating Contract lives in `CLAUDE.md`.)
