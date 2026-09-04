# KAAVAL — Team Integration Plan
### Branch strategy, merge order, and model/effort assignment for a 4-person parallel build

> This document is shared across all four builders. It is not owned by any one person's module — read it before starting, and don't let any individual build document silently contradict it.

---

## 1. Team and module ownership

| Person | Tool | Module | Owns (real seam) |
|---|---|---|---|
| **Ajay** | Claude Code Pro | Browser SDK | WebAuthn ceremonies, non-exportable session key generation, request canonicalization + signing, SDK protection-state UI |
| **Rohith** | Claude Code Pro | Gateway core | Session-to-key binding, nonce issuance, signature verification, replay prevention, the protected demo app, the attacker/replay console |
| **Adhi** | Claude Code Pro | Radar + Guardian | Mock-org exposure scoring, device-code policy, OAuth-consent policy |
| **Sai** | Codex (ChatGPT Plus) | Dashboard + Chronicle | Next.js dashboard, live event feed UI, Radar/incident display, the Chronicle LLM-explanation module |

This is a real architectural split, not an arbitrary division of files: each person owns exactly the external systems their module actually talks to (Ajay → the browser's own WebAuthn/Web Crypto APIs; Rohith → the database and the signature-verification path every other module's events flow through; Adhi → the mock organizational data and OAuth/device-code policy; Sai → the LLM API and the dashboard's rendering of everyone else's output).

## 2. Branch strategy

```text
main
 ├── stage-0/scaffold          (shared setup — see §3, merges first)
 ├── feature/browser-sdk       (Ajay)
 ├── feature/gateway-core      (Rohith)
 ├── feature/radar-guardian    (Adhi)
 └── feature/dashboard-chronicle (Sai)
```

- Branch names are exactly as above — this keeps CI, PR titles, and the merge order in §4 unambiguous.
- Nobody branches from `main` until Stage 0 (§3) is merged — every feature branch must start from the commit that contains the frozen `contracts` package and shared SQLite schema, or the contracts each person copied into their own build document will already be stale before they start.
- Commit messages reference task IDs from each person's build document (e.g. `T-AJ.3: sign canonical request envelope`), so a reviewer can trace any commit back to a specific, pre-agreed task rather than guessing intent.
- Nobody edits a file outside their own module's ownership listed in §1, with the single exception of the shared `contracts` package, which nobody edits after Stage 0 without the whole team agreeing synchronously first.

## 3. Stage 0 — shared scaffold (blocks everyone, keep it short)

One person (recommend Rohith, since the gateway is what the contracts primarily protect) does this first, alone, and merges to `main` before anyone else branches:

1. Repo skeleton: `backend/` (FastAPI app with empty `gateway/`, `radar/`, `guardian/`, `chronicle/` routers wired into `main.py`), `frontend/` (Next.js app shell), `sdk/` (browser SDK package skeleton).
2. `backend/contracts.py` — the Pydantic models for `SignedRequestEnvelope`, `SecurityEvent`, `RadarFinding`, `RadarReport`, `IncidentExplanation`, copied verbatim from TRD §6. This file is the literal source of truth; every module imports from it, nobody redefines a shadow copy.
3. SQLite schema migration creating the `events` table matching `SecurityEvent` and a `sessions` table for session-to-public-key binding.
4. A root `.env.example` listing every environment variable named across all four build documents.
5. Root `CLAUDE.md` and root `AGENTS.md` — see §5 below; both exist from Stage 0 onward so every tool picks up shared ground truth from its first session.

**VERIFY:** `uvicorn backend.main:app` starts with no errors; `GET /events/stream` returns an empty SSE stream; `sqlite3 kaaval.db ".tables"` shows `events` and `sessions`.

## 4. Merge order after Stage 0

Because every contract is frozen in Stage 0, all four feature branches can be *built* in parallel against mocks/fixtures of each other's real output — nobody is blocked waiting for someone else's code to exist. Merge order matters only for integration testing, not for who can start:

1. `feature/gateway-core` → `main` first. It's the module every `SecurityEvent` ultimately flows through, and the module Ajay's SDK calls directly — merging it first gives the rest of the team something real to integrate against instead of a mock.
2. `feature/browser-sdk` → `main` next, immediately integration-tested against the now-real gateway (Scene 2/3 of the demo: baseline replay succeeds, PulseLock replay fails).
3. `feature/radar-guardian` → `main` — independent of the first two, safe to merge any time after Stage 0; sequenced here only so the dashboard has real Radar/Guardian output to render rather than a fixture.
4. `feature/dashboard-chronicle` → `main` last, since it's the module that visibly depends on every other module's real output existing.

Each merge is gated on: the branch's own build document's Final Acceptance checklist passing, and a smoke test that `main` still boots after the merge (not a full re-run of every other module's tests — that's what Stage 0's frozen contracts are for).

## 5. Making sure every tool actually reads the shared context

Claude Code reads `CLAUDE.md` by convention. Codex reads `AGENTS.md` by convention. **Both files must exist at repo root from Stage 0 onward, and must carry the same GROUND TRUTH, anti-hallucination rules, and contract references** — not two different stories about the same project.

- Ajay, Rohith, and Adhi: your Claude Code sessions read `/CLAUDE.md` automatically. Each of your individual build documents' §A ("Operating Contract") is written to be pasted there — but since you share a repo, don't overwrite the root file with only your own module's context; append your module-specific ground truth under your own heading, and leave the shared sections (contracts, anti-hallucination rules, definition of done) intact for the others.
- Sai: Codex does not read `CLAUDE.md`. Copy the exact same Operating Contract content from your build document's §A into `/AGENTS.md` at repo root instead. If your Codex client also supports reading `CLAUDE.md` directly, leave both files in place rather than relying on that — `AGENTS.md` is the convention to depend on.
- Both files should open with an identical shared block (project one-liner, GROUND TRUTH stack choices, the four module owners from §1, and a pointer to `backend/contracts.py` as the literal source of truth for every schema) before branching into per-module specifics — this is what actually prevents Codex and Claude Code from silently drifting into two different mental models of the same system.

## 6. Model and effort assignment

Model access differs by plan, and this changes over time — verify current model names in your own tool before a long session, rather than trusting a name that may already be stale.

| Person | Task category | Recommended model | Why |
|---|---|---|---|
| Ajay | WebAuthn ceremonies, Web Crypto key generation, SDK UI (most tasks) | **Sonnet 5** (Claude Code default on Pro) | Well-specified browser-API integration and UI work — Sonnet's throughput matters more here than Opus's extra reasoning depth, and it's the model your Pro plan's main weekly allowance is built around. |
| Ajay | If WebAuthn origin-binding or key-extraction edge cases get genuinely ambiguous | Escalate to **Opus 5** for that specific task only | Pro includes Opus access but draws from a smaller, separate weekly cap — spend it only where reasoning depth, not throughput, is the bottleneck. |
| Rohith | FastAPI scaffolding, the demo app's CRUD routes, the attacker/replay console UI | **Sonnet 5** | Mechanical, well-specified implementation work. |
| Rohith | Signature verification, replay-prevention logic (nonce/sequence/timestamp checks), the canonical-string comparison logic | **Opus 5** | This is the single highest-stakes correctness surface in the entire system — every PRD acceptance criterion about a stolen cookie failing depends on this logic being exactly right. Worth the team's shared Opus allowance here specifically. |
| Adhi | Radar's checklist scoring engine, Guardian's device-code and OAuth-consent policy logic | **Sonnet 5** | Deterministic rule-engine code with a fully specified checklist (TRD §6.3, PRD FR-7 through FR-11) — well within Sonnet's strengths, and doesn't touch cryptographic correctness, so there's no strong case for spending the team's limited Opus allowance here. |
| Sai | Next.js/Tailwind dashboard UI, SSE consumption, Radar/incident rendering (most tasks) | Whatever Codex currently recommends as its default in your client — **verify in the Codex model picker before starting**, since OpenAI's naming changes frequently; as of this build, that's the current GPT-5.x "Codex" family at a medium/balanced reasoning effort. | Mechanical UI/data-fetching work; a balanced effort setting keeps iteration fast without under-thinking layout/state bugs. |
| Sai | Chronicle's prompt construction and grounding logic (turning `SecurityEvent` rows into a plain-language narrative without inventing facts not present in the events) | Step up to the **highest reasoning effort your Codex plan offers** for this task specifically | This is the one task in your module where subtle reasoning matters: TNFR-4 and NFR-3 require the explanation stay strictly grounded in the referenced events, and a model that reasons less carefully here is exactly how a hallucinated "cause" ends up in a judge-facing incident report. |

**General rule for all four:** default to the faster/cheaper model for mechanical, well-specified work, and reserve the deeper-reasoning option for the one or two tasks per module where getting the logic subtly wrong would actually break a PRD acceptance criterion — not for the module that "feels" hardest to write.

## 7. What "no errors on merge" actually depends on

Given the frozen contracts in §3-4, a clean merge isn't luck, it's a direct consequence of three things holding:

1. Nobody edited `backend/contracts.py` after Stage 0 without full-team agreement (§2).
2. Every module's own tests use the real contract types imported from that one file, not a locally redefined lookalike.
3. Each build document's own Final Acceptance checklist (in each person's document) passed *before* that branch was merged, not after.

If a contract genuinely needs to change mid-build, don't silently edit it on one branch — write a short amendment (see the project-blueprint skill's amendment format) naming exactly what changed and why, and merge that to `main` first so every branch is working from the same updated truth.
