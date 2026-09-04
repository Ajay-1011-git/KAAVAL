# DASHBOARD + CHRONICLE — Complete Build Instructions
### Drift-proof, hallucination-resistant prompts aligned to KAAVAL_PRD.md and KAAVAL_TRD.md

> **Purpose.** Build the Next.js dashboard (Radar findings, live blocked-attack feed, incident timeline) and the Chronicle module that turns already-decided security events into plain-language incident explanations. This is the module every judge actually looks at, so its correctness matters as much as its polish — Chronicle in particular must never say more than the events support.
>
> **Alignment guarantee.** If anything here conflicts with `KAAVAL_PRD.md` or `KAAVAL_TRD.md`, those documents win.
>
> **Partner module note.** You are a pure consumer of Rohith's `/events/stream` and Adhi's `/radar/report`, `/guardian/*` endpoints — you don't write to the `events` table, only read from it. You do not need their real running services to finish or verify most of your tasks; build and test against a local fixture server returning the exact shapes in §B.2. Do not touch `sdk/`, `backend/gateway/`, `backend/radar/`, or `backend/guardian/`, and do not modify `backend/contracts.py`.

---

# §A. Operating Contract — paste into **AGENTS.md** (this is the file your tool reads — see note below)

> **Note for Sai specifically:** Codex reads `AGENTS.md` at the repo root, not `CLAUDE.md`. Copy this entire section into `/AGENTS.md` verbatim, underneath the shared block that Rohith set up in Stage 0 (project one-liner, ground truth stack, module owners, pointer to `backend/contracts.py`). Don't rely on `CLAUDE.md` being read by your tool — if in doubt, keep both files present and identical for your module's section.

**What this module is.** A Next.js/Tailwind dashboard consuming the live `SecurityEvent` stream, Radar's report, and Guardian's decisions, plus a `chronicle/` backend module that calls an LLM to turn a set of already-decided events into a plain-language incident summary.

**GROUND TRUTH — do not silently change:**
- Chronicle runs strictly after a security decision already exists. It reads `SecurityEvent` rows; it never calls, blocks, allows, or reverses anything in `gateway/`, `radar/`, or `guardian/` (PRD FR-12, FR-13). If you find yourself wiring Chronicle's output back into an enforcement decision, stop — that's a design violation, not a feature.
- Chronicle's LLM call receives only fields already present in the referenced `SecurityEvent` rows — never raw user input, never full session tokens, never anything not already redacted structured data (PRD NFR-5, TRD TNFR-4).
- No behavioral biometrics or fingerprinting-based UI signal anywhere on the dashboard (PRD §4.2) — the dashboard displays decisions already made elsewhere, it doesn't introduce a new trust signal of its own.
- You own `frontend/` and `backend/chronicle/`. You do not modify `backend/contracts.py`.

**ANTI-HALLUCINATION RULES:**
1. Never invent the exact current API surface of your chosen LLM client library (model identifiers, request/response shapes) — verify the real, current API in-session before writing the Chronicle call. Model names and API shapes change; check rather than reuse a remembered one.
2. Never invent Radar/Guardian/gateway response shapes — they are fixed exactly in TRD §6 and this document's §B.2; if something doesn't match while integrating, that's a contract violation to flag, not something to silently adapt around.
3. If a requirement is ambiguous, ask one clarifying question rather than assuming.
4. Never fabricate a demo screenshot, test result, or LLM output — run the real thing and paste real output. For Chronicle specifically, paste an actual model response, not a plausible-sounding one you wrote yourself.

**ANTI-DRIFT RULES:**
- Only touch files listed in a task's "Files you may touch."
- Don't add a second, dashboard-local copy of any contract type — import from the fixture/shared definitions.
- Don't let Chronicle's prompt grow to include anything beyond the referenced events' fields — no "also consider general security best practices" style additions that would let the model reason beyond what it was actually given.

**QUALITY GATES:** every Chronicle summary is checked against a simple faithfulness rule before being shown — every named user, application, and reason mentioned in the summary must trace back to a field in one of the referenced events (write this as an actual automated check, not a manual read-through); the dashboard degrades gracefully (a clear "waiting for events" state, not a blank screen) if the SSE stream hasn't sent anything yet; no secrets in code.

**WORKING METHOD:** short plan first for multi-file tasks, implement, run real VERIFY commands and paste real output, commit as `T-SA.<n>: <short description>`.

**DEFINITION OF DONE:** builds cleanly, VERIFY passes with real pasted output (including a real LLM response for Chronicle tasks), `contracts.py` untouched, only permitted files touched.

---

# §B. Canonical Specifications

## B.1 Environment variables

```text
NEXT_PUBLIC_BACKEND_ORIGIN=http://localhost:8000
LLM_API_KEY=                     # Chronicle's key — verify the real current env var name your chosen client library expects before assuming this name is correct
CHRONICLE_FALLBACK_MODE=false    # flip to true to force the scripted fallback narrative, for rehearsal
```

## B.2 Data contracts (copied verbatim from TRD §6.2, §6.3, §6.4 — do not modify)

```typescript
interface SecurityEvent {
  event_id: string;
  timestamp: string;
  event_type: "session_bound" | "replay_attempted" | "proof_absent" | "signature_invalid"
    | "request_blocked" | "request_allowed" | "oauth_grant_blocked" | "oauth_grant_allowed"
    | "device_code_blocked";
  session_id: string | null;
  user_id: string | null;
  application_id: string | null;
  reason: string;
  detail: Record<string, string>;
  severity: "info" | "warning" | "blocked";
}

interface RadarFinding {
  finding_id: string;
  check: string;
  severity: "low" | "medium" | "high";
  affected_count: number;
  description: string;
  remediation: string;
}
interface RadarReport {
  organization_id: string;
  exposure_score: number;
  exposure_label: string;
  generated_at: string;
  findings: RadarFinding[];
}

interface IncidentExplanation {
  incident_id: string;
  related_event_ids: string[];
  summary: string;
  affected_user: string | null;
  affected_application: string | null;
  suggested_remediation: string[];
  generated_at: string;
}
```

Endpoints you consume (TRD §5): `GET /events/stream` (SSE), `GET /radar/report?org_id=mock-org-01`, `POST /chronicle/explain` (this one you build).

## B.3 File/folder structure

```text
frontend/
  app/
    page.tsx                # T-SA.1 — dashboard shell
    components/
      RadarPanel.tsx           # T-SA.2
      LiveEventFeed.tsx          # T-SA.3
      IncidentTimeline.tsx         # T-SA.4
      ChronicleExplanation.tsx       # T-SA.5 (renders the panel)
  lib/
    eventsClient.ts            # T-SA.3 — SSE hook
backend/
  chronicle/
    prompt.ts_or_.py             # T-SA.6 — prompt construction from events, grounded strictly
    fallback.py                    # T-SA.7 — scripted fallback narratives
    routes.py                        # T-SA.8 — POST /chronicle/explain
    faithfulness_check.py              # T-SA.9 — automated grounding check
```

---

# §C. Tasks

## T-SA.1 · Dashboard shell — `frontend/app/page.tsx` · P0 · depends: none

> **PROMPT**
> Goal: set up the Next.js app shell with a layout holding four regions: Radar panel, live event feed, incident timeline, Chronicle explanation panel.
> Files you may touch: `frontend/app/page.tsx`, `frontend/app/layout.tsx`.
> Requirements: Tailwind for styling, no component logic yet — this task is the shell and layout only. Verify the current real `create-next-app`/App Router conventions for your Next.js version in-session before scaffolding, rather than assuming a remembered file structure.
> **VERIFY:** `npm run dev` starts with no errors, all four empty regions render; paste real terminal output.

## T-SA.2 · Radar panel — `frontend/app/components/RadarPanel.tsx` · P0 · depends: T-SA.1

> **PROMPT**
> Goal: fetch and display the `RadarReport` from `GET /radar/report?org_id=mock-org-01`, clearly labeled as simulated organization data per NFR-5.
> Files you may touch: `frontend/app/components/RadarPanel.tsx`.
> Requirements: shows exposure score, label, and every finding with its check name, severity, and remediation — never collapse findings into a single unexplained number. Build and test against a local fixture returning a sample `RadarReport` matching §B.2's shape until Adhi's real endpoint exists.
> **VERIFY:** render against the fixture and paste a description of the rendered output (or a DOM snapshot) showing every field from §B.2's `RadarFinding` is visible.

## T-SA.3 · Live event feed — `frontend/lib/eventsClient.ts`, `frontend/app/components/LiveEventFeed.tsx` · P0 · depends: T-SA.1

> **PROMPT**
> Goal: subscribe to `GET /events/stream` via the browser's native `EventSource`, and render each `SecurityEvent` as it arrives.
> Files you may touch: `frontend/lib/eventsClient.ts`, `frontend/app/components/LiveEventFeed.tsx`.
> Requirements: verify the real current `EventSource` API in-session (it's a standard browser API, but check current MDN usage rather than assuming from memory) before wiring it up. Each event shows `event_type`, `reason`, `severity`, and timestamp, with `blocked` events visually distinct from `allowed`/`info`. Handle reconnection gracefully if the stream drops.
> **VERIFY:** against a local fixture SSE server emitting a few sample events, paste real output/description showing events appear live in the feed in the correct order.

## T-SA.4 · Incident timeline — `frontend/app/components/IncidentTimeline.tsx` · P1 · depends: T-SA.3

> **PROMPT**
> Goal: group related `SecurityEvent`s (same `session_id` or `application_id` within a short time window) into a chronological incident view.
> Files you may touch: `frontend/app/components/IncidentTimeline.tsx`.
> Requirements: pure grouping/display logic, no new data fetching beyond what T-SA.3 already streams.
> **VERIFY:** against a fixture set of events including one clear "attack sequence" (session_bound → replay_attempted → request_blocked), paste output showing they're grouped as one incident.

## T-SA.5 · Chronicle explanation panel — `frontend/app/components/ChronicleExplanation.tsx` · P1 · depends: T-SA.4, T-SA.8

> **PROMPT**
> Goal: a UI panel that, given a selected incident from T-SA.4, calls `POST /chronicle/explain` with the relevant `event_ids` and renders the returned `IncidentExplanation`.
> Files you may touch: `frontend/app/components/ChronicleExplanation.tsx`.
> Requirements: explicit loading state while the LLM call is in flight; explicit, honest display if the fallback narrative was used instead of a live LLM response (don't hide that distinction from the viewer).
> **VERIFY:** against T-SA.8's real endpoint, paste a real rendered `IncidentExplanation` for the replay-attack incident.

## T-SA.6 · Chronicle prompt construction — `backend/chronicle/prompt.py` · P0 · depends: none (needs `backend/contracts.py`)

> **PROMPT**
> Goal: build the LLM prompt strictly from the fields of the referenced `SecurityEvent` rows — nothing else.
> Files you may touch: `backend/chronicle/prompt.py`, its test file.
> Requirements: the prompt must explicitly instruct the model to only state facts present in the provided events and to say "not stated in the events" rather than infer anything not present (this is what makes NFR-3's honesty-of-output requirement checkable). Do not add general security knowledge or best-practice text into the prompt beyond what's needed to phrase the instruction — the summary's content should come entirely from the events.
> **VERIFY:** paste the real constructed prompt string for a sample two-event incident (session_bound + request_blocked), showing every fact in it traces to one of the two events.

## T-SA.7 · Scripted fallback narratives — `backend/chronicle/fallback.py` · P0 · depends: none

> **PROMPT**
> Goal: pre-written, reviewed fallback `IncidentExplanation` text for each of the demo's scripted incidents (replayed-cookie block, blocked OAuth grant), used automatically if the live LLM call fails, times out, or `CHRONICLE_FALLBACK_MODE=true`.
> Files you may touch: `backend/chronicle/fallback.py`.
> Requirements: fallback text must be accurate to what the demo's actual scripted events will contain — write it after T-RO.5's and T-AD.6's real event shapes exist, or coordinate the exact `reason` strings in advance so the fallback text matches them precisely.
> **VERIFY:** paste the fallback text for both scripted incidents and confirm they reference the actual `reason` values used elsewhere in the system (e.g. `"nonce_reused"`, `"unverified_publisher_with_offline_access_scope"`).

## T-SA.8 · Chronicle endpoint — `backend/chronicle/routes.py` · P0 · depends: T-SA.6, T-SA.7

> **PROMPT**
> Goal: `POST /chronicle/explain`, taking `{event_ids: string[]}`, fetching those `SecurityEvent` rows, building the prompt (T-SA.6), calling the LLM, and falling back to T-SA.7's scripted text on failure/timeout/`CHRONICLE_FALLBACK_MODE`.
> Files you may touch: `backend/chronicle/routes.py`, its test file.
> Requirements: verify the real, current API of whichever LLM client library you use (request shape, response parsing, timeout parameter) in this session before writing the call — do not assume a remembered SDK shape. Set an explicit timeout short enough that a slow call visibly falls back rather than hanging the panel.
> **VERIFY:** paste a real LLM response for the sample incident from T-SA.6, and separately paste the endpoint's output with `CHRONICLE_FALLBACK_MODE=true` showing the scripted fallback is returned instead.

## T-SA.9 · Faithfulness check — `backend/chronicle/faithfulness_check.py` · P1 · depends: T-SA.8

> **PROMPT**
> Goal: an automated check that every named user, application, and reason string in a Chronicle summary actually appears in one of its `related_event_ids`' event data, flagging (not necessarily blocking) any summary that mentions something not traceable.
> Files you may touch: `backend/chronicle/faithfulness_check.py`, its test file.
> Requirements: simple substring/entity-matching check is sufficient for the MVP — this doesn't need to be a second LLM call. Log a warning (not a hard failure) if a summary contains something unmatched, so the team can review it before the demo rather than the model silently drifting.
> **VERIFY:** test with one summary that passes cleanly and one deliberately-broken summary containing an invented fact, showing the check correctly flags the second; paste real output.

---

# §D. Build order

| Window | Tasks | Expected outcome |
|---|---|---|
| Day 1, hrs 0-3 | T-SA.1, T-SA.6, T-SA.7 | Dashboard shell up; Chronicle prompt logic and fallback text written (can be done before the UI, since they don't depend on it). |
| Day 1, hrs 3-6 | T-SA.2, T-SA.3 | Radar panel and live event feed working against fixtures. |
| Day 1, hrs 6-8 | T-SA.8 | Chronicle endpoint live, both real and fallback paths verified. |
| Day 2, hrs 0-3 | T-SA.4 | Incident timeline groups related events correctly. |
| Day 2, hrs 3-5 | T-SA.5 | Chronicle explanation panel wired to the real endpoint. |
| Day 2, hrs 5-6 | T-SA.9 | Faithfulness check catches a deliberately broken test case. |
| Day 2, hrs 6-8 | Integration with Rohith's and Adhi's real endpoints (post-merge) | Swap fixtures for real backend calls; full live demo path works end to end. |

---

# §E. Final acceptance

1. ✅ Dashboard renders all four regions with real (or fixture, pre-merge) data (T-SA.1-T-SA.4).
2. ✅ Radar findings are shown individually with check name, severity, remediation — never a bare score (T-SA.2, NFR-2).
3. ✅ Live events appear on the feed with bounded delay, correctly distinguishing blocked from allowed (T-SA.3).
4. ✅ Chronicle's prompt is built strictly from event fields, and the live LLM call has a working, accurate scripted fallback (T-SA.6-T-SA.8).
5. ✅ The faithfulness check correctly flags an ungrounded summary in its own test (T-SA.9).
6. ✅ The UI never conflates Chronicle's explanation with an enforcement decision — the panel is visibly explanatory, not a control.
7. ✅ `contracts.py` untouched; only files under `frontend/` and `backend/chronicle/` were modified.
