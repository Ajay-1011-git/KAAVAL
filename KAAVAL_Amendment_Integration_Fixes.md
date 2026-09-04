# KAAVAL — Amendment: Integration and demo-readiness fixes

> This is a change request against the four build documents and `backend/contracts.py`, not a fresh build — all four modules are functionally complete per their own Final Acceptance checklists. This amendment closes the gap between "every module works in isolation" and "the live demo actually runs in a real browser end to end."

## STEP 0 — Audit before touching anything

Before starting any fix below, each owner should confirm current real state against their own module (not against what the build doc assumed): run the app, hit the actual endpoints, and note anything that's already diverged further from these documents than the audit found — treat the six findings as a floor, not a ceiling.

## What actually changed (verified, not assumed)

A post-merge audit (your own agentic review, cross-checked against the original blueprint above) found: the browser SDK has no consumer inside `frontend/`; `sdk/package.json` references a non-existent entry file; there's no root README; the WebAuthn RP ID/origin defaults don't match a real local-dev browser session; Guardian's OAuth-block path has no live demo trigger; and two contract-level gaps (`device_code_allowed` missing from the `SecurityEvent` enum, `db.py` resolving `DB_PATH` at import time) were correctly left open rather than silently resolved by one person.

## Required changes

### FIX-1 · New demo page — owner: Ajay, with Rohith available for final integration
**Old:** no task existed that imports `sdk/` into `frontend/`.
**New:** add `frontend/app/demo/page.tsx` — a real, minimal page that: calls `registerPasskey()`/`loginWithPasskey()` from the SDK, shows the SDK's protection-state indicator, and fires one signed request via `kaavalFetch` against Rohith's real `/api/transfer` demo route. This is the literal browser half of PRD acceptance criteria 1-2 — until this exists, that path is only proven in Python.
**VERIFY:** in a real browser, complete a passkey registration + login, see the indicator flip to "Protected," and see one signed request succeed against the real gateway. Paste a real network-tab screenshot or HAR export, not a description.

### FIX-2 · SDK entry point — owner: Ajay
**Old:** `package.json` points at `src/index.ts`, which doesn't exist.
**New:** create `sdk/src/index.ts` re-exporting the public API: `generateSessionKeyPair`, `registerPasskey`, `loginWithPasskey`, `kaavalFetch`, the indicator mount function, and the `KaavalSdkConfig` type.
**VERIFY:** `import { loginWithPasskey } from "@kaaval/sdk"` (or your actual package name) resolves and typechecks from `frontend/`; paste real build output.

### FIX-3 · Root README — owner: whoever's free first (this is intentionally not gated on anyone else)
**New:** `README.md` at repo root covering: prerequisites, `.env` copy step for each module's env vars (pull from each build doc's §B.1), the exact start order (`backend` → `sdk` build → `frontend`), and a link to `KAAVAL_Team_Integration_Plan.md` for anyone touching more than one module.
**VERIFY:** someone who didn't build the stack follows the README from a clean clone and gets the full demo running; note where they got stuck, if anywhere.

### FIX-4 · WebAuthn RP ID / origin for real local-browser demo — owner: Rohith + Ajay together (both sides must agree, don't fix one side alone)
**Old:** `WEBAUTHN_RP_ID=kaaval-demo.local` in Rohith's `.env`, matching value assumed in Ajay's SDK config — neither matches an actual `localhost` dev session.
**New:** for local/demo use, set `WEBAUTHN_RP_ID=localhost` and `WEBAUTHN_RP_ORIGIN=http://localhost:<your frontend port>` in both places — WebAuthn's spec explicitly permits `localhost` as an RP ID for exactly this case. If you'd rather keep a custom domain for a more realistic-looking demo, add a hosts-file entry mapping it to `127.0.0.1` and confirm HTTPS or a browser flag isn't required for your target browser — verify this in-session against current browser behavior rather than assuming.
**VERIFY:** a real passkey ceremony completes in an actual browser against the actual serving origin; paste the real WebAuthn error-free console output.

### FIX-5 · Live Guardian demo trigger — owner: Adhi + Sai together
**Old:** Guardian's policy and endpoints are real and unit-tested; nothing in the attacker console or dashboard fires a live OAuth consent request.
**New:** add one button on the dashboard (or one script alongside `backend/attacker_console/`) that POSTs a pre-built malicious `OAuthGrantRequest` (unverified publisher, broad scopes, not allowlisted) to `/guardian/oauth/evaluate`, and one that POSTs a clean one — so both the block and the allow path are visibly demonstrable, matching PRD acceptance criterion 6.
**VERIFY:** trigger both live from the UI/script, confirm the block appears on the live event feed with the correct `reason`, and confirm a real `IncidentExplanation` can be generated for it via Chronicle.

### FIX-6a · Add `device_code_allowed` to the frozen contract — owner: whole team agrees, then Rohith applies it to `contracts.py`
**Old:** `SecurityEvent.event_type` has `device_code_blocked` with no allowed counterpart.
**New:** add `"device_code_allowed"` to the `Literal` in `backend/contracts.py`. Propagate the type-union change to Adhi's `guardian/routes.py` (T-AD.8, write the event on the allow path too) and Sai's TypeScript mirror of the type (`frontend`/`backend/chronicle` wherever it's duplicated).
**VERIFY:** a device-code request that passes all policy conditions now produces a real `device_code_allowed` row in `events`; paste real output.

### FIX-6b · `db.py` DB_PATH resolution — owner: Rohith (contained to his module, but flag the decision to the team first since Adhi's and Sai's tests may assume current behavior)
**Old:** `DB_PATH` resolved at module import time.
**New:** resolve it lazily — read the env var inside a function (or FastAPI dependency) called at app startup / first connection, not at module import — so tests and any future multi-environment run can override it cleanly.
**VERIFY:** a test that sets `DB_PATH` to a temp file *after* importing `db.py` successfully uses the temp file, not whatever was resolved at import time; paste real output.

## Open questions — do not guess, ask if unresolved

None of the six require a product decision beyond what's specified above — all are implementation fixes with a stated correct direction. If FIX-4's choice between `localhost` and a custom hosts-file domain affects how you want the demo to *look* to judges (a real-looking domain vs. plain `localhost` in the address bar), that's a genuine team call worth 30 seconds of discussion, not a default to accept silently.

## VERIFY (whole amendment)

Once all six are applied: run the full demo script (below) start to finish in a real browser, with zero steps performed only in a test file or only against a mock — paste the real run.
