# Technical Requirements Document (TRD)
## KAAVAL

**Implementation target:** Web application (browser SDK + server middleware + dashboard), single backend process for MVP

---

## 1. Purpose and Scope

Defines how KAAVAL is actually built: the stack, the component boundaries, and — most importantly for a four-person parallel build — the exact, frozen data contracts at every seam between modules. Every schema in §6 is canonical. No build task may redefine or diverge from it; a change to a contract is a decision the whole team makes together, not something one branch does locally.

## 2. System Context

Four compute/interaction domains: the **browser** (WebAuthn ceremonies, non-exportable key generation, request signing), the **backend** (a single FastAPI process containing the Gateway, Radar, and Guardian modules as separate routers sharing one database), the **dashboard** (a Next.js frontend consuming events and reports), and one **external dependency**, the LLM API used only by Chronicle.

The single governing architectural principle: **the security decision and the explanation of that decision are produced by two different mechanisms that never run in the other's place.** PulseLock's verification and Guardian's policy evaluation are deterministic code paths with no model in the loop. Chronicle's LLM call happens strictly after a decision already exists, reads only already-decided structured events, and cannot alter, approve, or reverse anything. This isn't a style choice — it's what makes every blocked-attack claim in the demo something the team can actually defend under a judge's follow-up question.

## 3. Technology Stack — Selection and Justification

| Layer | Choice | Justification |
|---|---|---|
| Frontend / dashboard | Next.js + React + Tailwind CSS | Server-Sent Events client and a live-updating findings/incident feed are straightforward in React; Tailwind keeps the four-person build's UI visually consistent without a shared design system to maintain. |
| Backend | FastAPI (Python), single process, three routers (gateway, radar, guardian) plus a chronicle module | Async support means the signature-verification path isn't blocked by the Chronicle module's LLM call happening elsewhere in the same process; a single process avoids inter-service network calls that would otherwise become a live-demo dependency and a merge-coordination headache for a four-person split under time pressure. |
| Database | SQLite for the MVP (Postgres-compatible schema so a later swap is mechanical) | The full success-metric suite (§7 of the PRD) runs against a local demo environment; SQLite removes a network hop from the < 100 ms verification-overhead budget (NFR-4) and removes "is the DB reachable" as a live-demo risk. |
| Browser cryptography | Web Crypto API | The only non-exportable, browser-native mechanism for generating a session key pair that never leaves the device — this is the literal property PulseLock's proof-of-possession model depends on (PRD FR-1). |
| Authentication | WebAuthn / passkeys | The only authentication method in the comparison table that is not phishable by AiTM relay, because the signed challenge is bound to the real origin by the browser itself, not by anything the server can be tricked about. |
| Live dashboard updates | Server-Sent Events | One-directional (server → dashboard) event flow is all the dashboard needs; SSE is simpler to reason about under demo pressure than a bidirectional WebSocket the team doesn't need. |
| Chronicle's LLM call | Claude API, called only with redacted, structured event JSON | Structured-input, bounded-output summarization is exactly the task the operating contract's honesty-of-output rule (NFR-3) requires be checkable — a small, auditable prompt is easier to keep grounded than a general-purpose chat interface. |

## 4. Component Architecture

```text
Browser
 ├── WebAuthn ceremony (register / login)
 ├── Web Crypto API: generate non-exportable session key pair
 ├── Request canonicalizer + signer
 └── SDK protection-state indicator
        │  (Signed Request Envelope — see §6.1)
        ▼
FastAPI backend (single process, one SQLite database)
 ├── gateway/   — session-to-key binding, nonce issuance,
 │                signature verification, replay prevention,
 │                protected demo app routes
 ├── radar/     — mock-org exposure scoring
 ├── guardian/  — device-code + OAuth-consent policy
 ├── events.py  — shared, canonical: every module writes
 │                SecurityEvent rows here (see §6.2) — frozen
 │                contract, owned by no one branch
 └── chronicle/ — reads events, calls the LLM, returns
                  IncidentExplanation (see §6.4)
        │  (SecurityEvent stream via SSE, RadarReport, IncidentExplanation)
        ▼
Next.js dashboard
 ├── Live blocked-attack feed (SSE from /events/stream)
 ├── Radar findings panel
 ├── Incident timeline
 └── Chronicle explanation panel

Attacker console (small standalone tool) → replays a captured
cookie against gateway/ in both baseline and PulseLock-protected
modes, to make the before/after demonstrable rather than asserted.
```

## 5. API Contracts

| Method | Path | Purpose | Owner |
|---|---|---|---|
| POST | `/auth/webauthn/register/begin` `/finish` | WebAuthn passkey registration; `finish` also authorizes the newly generated session public key | Rohith (gateway) / Ajay (browser SDK client) |
| POST | `/auth/webauthn/login/begin` `/finish` | WebAuthn login; `finish` binds the session to the submitted public key | Rohith / Ajay |
| POST | `/auth/nonce` | Issues one single-use, short-lived nonce for the next signed request | Rohith |
| ANY | `/api/*` (demo app routes, e.g. `/api/transfer`) | Protected application routes; require the `X-KAAVAL-Proof` header (§6.1) when PulseLock mode is active; baseline mode accepts a plain cookie for the negative-control demo | Rohith |
| GET | `/radar/report?org_id=mock-org-01` | Returns the current `RadarReport` (§6.3) | Adhi |
| POST | `/guardian/oauth/evaluate` | Evaluates a simulated OAuth consent request against policy, returns allow/block + reason, writes a `SecurityEvent` | Adhi |
| POST | `/guardian/device-code/evaluate` | Evaluates a simulated device-code request against policy, same response shape | Adhi |
| GET | `/events/stream` | SSE stream of `SecurityEvent` objects as they are written | Rohith hosts it; Sai consumes it |
| POST | `/chronicle/explain` | Body `{ "event_ids": string[] }`; returns an `IncidentExplanation` (§6.4) | Sai |

**Anti-hallucination note for §5:** the exact field names and ceremony shapes of the WebAuthn `begin`/`finish` calls depend on whatever WebAuthn server library is actually chosen (e.g. `py_webauthn`). Ajay and Rohith must verify that library's real current API in-session before writing code against it — the shapes above are the contract's *purpose*, not a literal schema to copy blind.

## 6. Data Models

These are the literal, frozen contracts. Copy verbatim into every build document that touches them; do not modify locally.

### 6.1 Signed Request Envelope — contract between Ajay (browser SDK) and Rohith (gateway)

```typescript
// Sent as header X-KAAVAL-Proof, base64(JSON.stringify(envelope))
interface SignedRequestEnvelope {
  session_id: string;
  method: string;        // e.g. "POST" — must equal the actual HTTP method
  origin: string;        // e.g. "https://kaaval-demo.local" — the real origin
  path: string;           // e.g. "/api/transfer"
  body_hash: string;      // hex SHA-256 of the exact raw request body bytes
  nonce: string;          // from POST /auth/nonce, single-use
  sequence: number;       // strictly increasing per session
  timestamp: string;      // ISO-8601 UTC, e.g. "2026-09-04T18:40:00Z"
  signature: string;      // base64, over the canonical string below
}
```

Canonical string to sign (fixed order, newline-joined, no other format is valid):

```text
session_id\nmethod\norigin\npath\nbody_hash\nnonce\nsequence\ntimestamp
```

Server verification (Rohith), in order — matches PRD FR-5 exactly:
1. Session is active.
2. Signature is valid against the public key bound to `session_id`.
3. Asserted `method` / `origin` / `path` equal what the server actually received.
4. Asserted `body_hash` equals SHA-256 of the actual received body.
5. `nonce` was issued by the server and is unused.
6. `sequence` is valid (strictly greater than the last accepted sequence for this session).
7. `timestamp` is within the permitted freshness window.

Any failure → reject the request, write a `SecurityEvent` with the specific failed check as `reason`, never a generic "invalid request."

### 6.2 SecurityEvent — shared contract, written by Rohith's gateway and Adhi's guardian, read by Sai's dashboard and Chronicle

```typescript
interface SecurityEvent {
  event_id: string;       // UUID
  timestamp: string;      // ISO-8601 UTC
  event_type:
    | "session_bound"
    | "replay_attempted"
    | "proof_absent"
    | "signature_invalid"
    | "request_blocked"
    | "request_allowed"
    | "oauth_grant_blocked"
    | "oauth_grant_allowed"
    | "device_code_blocked";
  session_id: string | null;
  user_id: string | null;
  application_id: string | null;   // relevant for Guardian events
  reason: string;                   // e.g. "nonce_reused", "body_hash_mismatch", "unverified_publisher"
  detail: Record<string, string>;   // small structured values only — never raw credentials or full tokens
  severity: "info" | "warning" | "blocked";
}
```

This table is the single event bus for the whole system. **Do not create a second events table or a parallel event shape** — Radar findings and incident explanations reference `event_id`s from this one table.

### 6.3 RadarReport — produced by Adhi, read by Sai

```typescript
interface RadarFinding {
  finding_id: string;
  check: string;            // exact check name, e.g. "phishable_mfa_active"
  severity: "low" | "medium" | "high";
  affected_count: number;
  description: string;
  remediation: string;
}

interface RadarReport {
  organization_id: string;  // always a clearly simulated id, e.g. "mock-org-01"
  exposure_score: number;   // 0-100
  exposure_label: string;   // "Low" | "Medium" | "High"
  generated_at: string;
  findings: RadarFinding[];
}
```

### 6.4 IncidentExplanation — produced by Sai's Chronicle module

```typescript
interface IncidentExplanation {
  incident_id: string;
  related_event_ids: string[];   // must reference real SecurityEvent.event_id values
  summary: string;                // plain-language paragraph, grounded only in the referenced events
  affected_user: string | null;
  affected_application: string | null;
  suggested_remediation: string[];
  generated_at: string;
}
```

## 7. Performance Engineering

- Nonce issuance and signature verification happen entirely in-process against SQLite with indexed lookups on `session_id` and `nonce` — no network hop, which is what keeps NFR-4's < 100 ms budget realistic on demo hardware.
- Chronicle's LLM call is never in the request path of any PulseLock or Guardian decision; it is invoked only when the dashboard explicitly asks for an incident explanation, so a slow LLM response cannot ever make an attack blocked-or-allowed decision look slow.
- The SSE stream sends only newly-written `SecurityEvent` rows (a `since_event_id` cursor), not a full replay of history on every dashboard refresh, so the live feed stays responsive as the demo generates more events.

## 8. Reliability and Bug-Prevention Strategy

- **Type safety across the stack:** the schemas in §6 are the single source of truth; Python (Pydantic) and TypeScript definitions on each side of a contract must be generated or hand-kept identical to them, never redefined ad hoc per module.
- **Validation at every external boundary:** every field in the Signed Request Envelope is validated before use (nonce existence, sequence monotonicity, timestamp window) — a malformed or partial envelope is a rejection, not a best-effort parse.
- **Explicit fallback for the one component with an external dependency:** Chronicle's LLM call has a scripted, pre-verified fallback narrative for each demo-scripted incident, used automatically if the live call fails, times out, or is slow — this is written and tested before judging, not improvised live.
- **Demo-critical-path independence:** the entire PulseLock/Guardian/Radar decision path runs locally against SQLite with zero third-party network calls; the *only* thing outside the team's control during the demo is Chronicle's LLM call, and it is explicitly not required for any of the PRD's core acceptance criteria (§11, items 1-6 of the PRD) to pass.
- **No secrets in code:** LLM API keys and any WebAuthn relying-party configuration live in environment variables (see each build document's §B.1), never committed.

## 9. Non-Functional Technical Requirements

| ID | Requirement |
|---|---|
| TNFR-1 | Median signature-verification latency < 100 ms on local demo hardware. |
| TNFR-2 | 100% of malformed or missing `X-KAAVAL-Proof` envelopes are rejected, never silently accepted. |
| TNFR-3 | The `SecurityEvent` schema (§6.2) has exactly one canonical definition in the codebase, imported by every module that writes or reads it. |
| TNFR-4 | Chronicle's LLM prompt includes only fields from already-retrieved `SecurityEvent` records — no free-text user input is ever passed to the LLM unredacted. |
| TNFR-5 | The system functions end-to-end (PulseLock verification, Guardian evaluation, Radar report, dashboard feed) with zero internet connectivity, except for the single Chronicle LLM call, which has a working local fallback per §8. |
