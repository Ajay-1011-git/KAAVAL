# RADAR + GUARDIAN — Complete Build Instructions
### Drift-proof, hallucination-resistant prompts aligned to KAAVAL_PRD.md and KAAVAL_TRD.md

> **Purpose.** Build the two deterministic policy engines: Radar (pre-attack exposure scoring against a mock organization) and Guardian (device-code and OAuth-consent policy enforcement). Both are self-contained relative to the live request path — neither depends on PulseLock's signature verification to function or be demonstrated.
>
> **Alignment guarantee.** If anything here conflicts with `KAAVAL_PRD.md` or `KAAVAL_TRD.md`, those documents win.
>
> **Partner module note.** You write to the same `events` table Rohith's gateway owns the schema for (`backend/contracts.py`, frozen after Stage 0), and Sai's dashboard reads your `RadarReport` and your Guardian-triggered `SecurityEvent`s. You do not need Rohith's or Sai's real code to finish or verify your own tasks. Do not touch `sdk/`, `frontend/`, `backend/gateway/`, or `backend/chronicle/`, and do not modify `backend/contracts.py`.

---

# §A. Operating Contract — paste into CLAUDE.md

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

---

# §B. Canonical Specifications

## B.1 Environment variables

```text
MOCK_ORG_ID=mock-org-01     # used everywhere Radar output is labeled, per NFR-5
```

## B.2 Data contracts (copied verbatim from TRD §6.2 and §6.3 — do not modify)

```python
# import from backend/contracts.py — do not redefine
class SecurityEvent(BaseModel):
    event_id: str
    timestamp: str
    event_type: Literal[..., "oauth_grant_blocked", "oauth_grant_allowed", "device_code_blocked", ...]
    session_id: Optional[str]
    user_id: Optional[str]
    application_id: Optional[str]
    reason: str
    detail: dict
    severity: Literal["info", "warning", "blocked"]
```

```python
# backend/radar/models.py — new file, you own this
class RadarFinding(BaseModel):
    finding_id: str
    check: str
    severity: Literal["low", "medium", "high"]
    affected_count: int
    description: str
    remediation: str

class RadarReport(BaseModel):
    organization_id: str
    exposure_score: int          # 0-100
    exposure_label: Literal["Low", "Medium", "High"]
    generated_at: str
    findings: list[RadarFinding]
```

Radar's fixed checklist (PRD FR-7 — do not add or remove checks without a team decision):
`phishable_mfa_active`, `passkeys_unenforced`, `weak_fallback_bypasses_passkey`, `device_code_unrestricted`, `unknown_oauth_apps`, `excessive_app_permissions`, `unmonitored_admin_accounts`, `conditional_access_exclusions`, `long_lived_sessions`.

Guardian's OAuth evaluation inputs (PRD FR-10):
```python
class OAuthGrantRequest(BaseModel):
    application_id: str
    application_name: str
    publisher_verified: bool
    requested_scopes: list[str]
    redirect_uri: str
    offline_access_requested: bool
    is_org_allowlisted: bool
```

## B.3 File/folder structure

```text
backend/
  radar/
    models.py           # T-AD.1
    mock_org.py           # T-AD.2 — the simulated 100-account dataset
    scoring.py             # T-AD.3 — the checklist engine
    routes.py                # T-AD.4 — GET /radar/report
  guardian/
    models.py                # T-AD.5
    oauth_policy.py            # T-AD.6
    device_code_policy.py        # T-AD.7
    routes.py                      # T-AD.8 — POST /guardian/oauth/evaluate, /device-code/evaluate
```

---

# §C. Tasks

## T-AD.1 · Radar data models — `backend/radar/models.py` · P0 · depends: none (needs `backend/contracts.py` to exist from Stage 0)

> **PROMPT**
> Goal: define `RadarFinding` and `RadarReport` exactly per §B.2.
> Files you may touch: `backend/radar/models.py`.
> Requirements: Pydantic models, field names and types exactly as specified.
> **VERIFY:** import and instantiate both models with sample data in a quick script; paste real output.

## T-AD.2 · Mock organization dataset — `backend/radar/mock_org.py` · P0 · depends: T-AD.1

> **PROMPT**
> Goal: a clearly-labeled simulated organization of 100 accounts with realistic weak-configuration patterns for Radar to evaluate, per PRD §11's MVP simulation guidance (accounts with phishable MFA, Conditional Access exclusions, unknown OAuth grants, risky admin accounts).
> Files you may touch: `backend/radar/mock_org.py`.
> Requirements: a static, deterministic dataset (not randomly regenerated each run, so the demo score is reproducible) with `organization_id="mock-org-01"`, roughly matching the example output shape in the design docs (e.g. ~18 accounts with phishable MFA, ~7 with weak fallback, device-code enabled, a handful of unknown apps, a couple of unmonitored admins). Comment clearly that this is entirely simulated data.
> **VERIFY:** load the dataset and print summary counts per weak-config category; paste real output.

## T-AD.3 · Checklist scoring engine — `backend/radar/scoring.py` · P0 · depends: T-AD.2

> **PROMPT**
> Goal: implement the fixed nine-check checklist from §B.2, producing a `RadarReport` from the mock org dataset.
> Files you may touch: `backend/radar/scoring.py`, its test file.
> Requirements: each check is a pure function taking the mock org data and returning zero or one `RadarFinding` (with `affected_count` and a specific `remediation`), never an unexplained numeric adjustment. The overall `exposure_score` is a deterministic, documented function of the individual findings' severities and affected counts — write down the exact formula in a code comment so it's auditable, not a black box.
> **VERIFY:** run the scoring engine against the T-AD.2 dataset and paste the real resulting `RadarReport` JSON, confirming every finding traces to a named check.

## T-AD.4 · Radar report endpoint — `backend/radar/routes.py` · P0 · depends: T-AD.3

> **PROMPT**
> Goal: `GET /radar/report?org_id=mock-org-01` returning the `RadarReport` from T-AD.3.
> Files you may touch: `backend/radar/routes.py`, its test file.
> Requirements: 404 for any `org_id` other than the known mock org (there is no live-tenant mode in this MVP — don't silently accept an arbitrary org id).
> **VERIFY:** curl the endpoint and paste real JSON output.

## T-AD.5 · Guardian data models — `backend/guardian/models.py` · P0 · depends: none

> **PROMPT**
> Goal: define `OAuthGrantRequest` per §B.2 and an equivalent `DeviceCodeRequest` model (application_id, device_registered: bool, code_ttl_seconds: int, is_allowlisted: bool, is_sensitive_resource: bool, admin_approved: bool).
> Files you may touch: `backend/guardian/models.py`.
> **VERIFY:** instantiate both models with sample data; paste real output.

## T-AD.6 · OAuth-consent policy — `backend/guardian/oauth_policy.py` · P0 · depends: T-AD.5

> **PROMPT**
> Goal: implement the deterministic OAuth-consent evaluation from PRD FR-10.
> Files you may touch: `backend/guardian/oauth_policy.py`, its test file.
> Requirements: `evaluate_oauth_grant(req: OAuthGrantRequest) -> tuple[Literal["allow","block"], str]` — blocks if publisher is unverified AND scopes include high-risk permissions (e.g. broad mail read/send, offline access) unless `is_org_allowlisted` is true; returns a specific, human-readable `reason` string naming exactly which condition failed (e.g. `"unverified_publisher_with_offline_access_scope"`), matching the example block reason in the design docs. No numeric risk score — pure if/else policy, per this module's GROUND TRUTH.
> **VERIFY:** unit tests for at least: (a) unverified publisher + broad scopes + not allowlisted → blocked with correct reason, (b) verified publisher + narrow scopes → allowed, (c) unverified publisher but org-allowlisted → allowed. Paste real test output for all three.

## T-AD.7 · Device-code policy — `backend/guardian/device_code_policy.py` · P0 · depends: T-AD.5

> **PROMPT**
> Goal: implement the default-block device-code policy from PRD FR-9.
> Files you may touch: `backend/guardian/device_code_policy.py`, its test file.
> Requirements: `evaluate_device_code(req: DeviceCodeRequest) -> tuple[Literal["allow","block"], str]` — blocked unless allowlisted app AND registered device AND short-lived single-use code AND (not sensitive resource OR admin approved). Default is block; every allow path must satisfy all stated conditions.
> **VERIFY:** unit tests for: (a) no exception conditions met → blocked, (b) all conditions met, non-sensitive → allowed, (c) all conditions met but sensitive without admin approval → blocked. Paste real output.

## T-AD.8 · Guardian evaluation endpoints — `backend/guardian/routes.py` · P0 · depends: T-AD.6, T-AD.7

> **PROMPT**
> Goal: `POST /guardian/oauth/evaluate` and `POST /guardian/device-code/evaluate`, calling the respective policy functions and writing a `SecurityEvent` (`oauth_grant_blocked`/`oauth_grant_allowed`/`device_code_blocked`) for every evaluation via the shared `write_event` helper in `backend/events.py`.
> Files you may touch: `backend/guardian/routes.py`, its test file. You may call, but not modify, `backend/events.py`'s `write_event`.
> Requirements: response includes the decision and the specific reason; a `SecurityEvent` row is always written regardless of allow/block outcome, so the dashboard's timeline is complete.
> **VERIFY:** curl both endpoints with a blocking and an allowing payload each, and confirm real rows appear in the `events` table afterward; paste real output for both.

---

# §D. Build order

| Window | Tasks | Expected outcome |
|---|---|---|
| Day 1, hrs 0-3 | T-AD.1, T-AD.2 | Data models defined, mock org dataset built and reproducible. |
| Day 1, hrs 3-7 | T-AD.3 | Full checklist scoring engine works, exposure score formula documented. |
| Day 1, hrs 7-8 | T-AD.4 | Radar report endpoint live. |
| Day 2, hrs 0-2 | T-AD.5 | Guardian data models defined. |
| Day 2, hrs 2-5 | T-AD.6 | OAuth-consent policy passes all three test cases. |
| Day 2, hrs 5-7 | T-AD.7 | Device-code policy passes all three test cases. |
| Day 2, hrs 7-8 | T-AD.8 | Both Guardian endpoints live and writing real events. |

---

# §E. Final acceptance

1. ✅ Radar's exposure score and every finding trace to a named, documented check — no opaque scoring (T-AD.3).
2. ✅ `GET /radar/report` returns real, reproducible output labeled as simulated (T-AD.4).
3. ✅ OAuth-consent policy correctly blocks/allows all three test scenarios in T-AD.6.
4. ✅ Device-code policy is default-block and correctly handles all three test scenarios in T-AD.7.
5. ✅ Every Guardian evaluation writes a real `SecurityEvent` row (T-AD.8).
6. ✅ No probabilistic/ML/LLM component appears anywhere in either module's decision path.
7. ✅ `contracts.py` untouched; only files under `backend/radar/` and `backend/guardian/` were modified.
