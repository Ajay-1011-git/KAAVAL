# Product Requirements Document (PRD)
## KAAVAL

**Document status:** Final (solution locked — this document formalizes decisions already made, it does not introduce new ones)
**Track / context:** Industry 4.0 — Automation for Good, Sector: IT Security and Cyber Resilience
**Aligned goals/standards:** OWASP session-management and authentication guidance; WebAuthn/FIDO2 (W3C); OAuth 2.0 (RFC 6749)

---

## 1. Problem Statement

The track's brief asks for automation that can keep operating, adapting, recovering, or protecting itself when the infrastructure around it is under attack — including cases where the attack lands on the system the automation is assigned to protect, or on the automation itself.

Identity and session state is exactly that kind of foundational infrastructure. Every other automated system in an organization — the ticketing bot, the CI/CD pipeline, the finance workflow, the admin console — implicitly trusts "this request carries a valid authenticated session" as its proof that the request is legitimate. Modern Multi-Factor Authentication (MFA) was built to make that initial trust decision hard to forge. It has succeeded at that single moment and failed at everything after it: once a session cookie exists, MFA is never checked again for the life of that session, and the cookie itself is a **bearer credential** — whoever holds it is trusted, regardless of how they obtained it.

**Reverse-proxy phishing (Adversary-in-the-Middle / AiTM)** exploits precisely this gap. The attacker's server sits between the victim and the real site, relaying the login — including the MFA step — live, in both directions. Password and MFA both succeed, because they really were checked by the real server. The attacker's proxy simply captures the resulting session cookie as it passes through and reuses it from anywhere, with no MFA check ever re-triggered. This means the compromise doesn't happen at the credential layer at all — it happens at the layer every downstream automated system silently trusts. An organization can have phishing-resistant MFA everywhere and still lose control of its own automation the moment a session token becomes copyable.

Existing defenses (stronger MFA methods, browser or network fingerprinting, risk-scoring based on login patterns) all still validate identity once, at login, and then hand back a plain bearer token — none of them close the actual gap, which is what happens to trust *after* the token is issued.

## 2. Goals and Objectives

| Goal ID | Description |
|---|---|
| G-1 | Make a stolen or replayed session cookie insufficient on its own to act as the authenticated user. |
| G-2 | Make phishing-resistant login (WebAuthn/passkeys) actually resistant to AiTM relay, not just to classic credential-recording phishing. |
| G-3 | Close the two authorization-layer bypasses (device-code phishing, malicious OAuth consent) that succeed without stealing any credential at all. |
| G-4 | Surface weak identity configurations before they are exploited, with findings a non-specialist can act on. |
| G-5 | Turn a blocked attack into a plain-language, human-reviewable incident record without letting any model make the underlying security decision. |

## 3. Stakeholders and Target Users

| Stakeholder | Relationship to the system |
|---|---|
| End user (employee logging into a protected application) | Authenticates via passkey; session behavior should be invisible when legitimate, and safely blocked when hijacked. |
| Security/IT administrator | Reads Radar findings, configures Guardian policy, reviews Chronicle incident reports. |
| Application owner / engineering team integrating KAAVAL | Deploys the browser SDK and server middleware into their own app. |
| Judge / evaluator (hackathon context) | Needs to see the actual attack fail live, not be told it would fail. |

**User stories**

- As an **end user**, I want my login and every subsequent action to be protected without extra taps or codes to type, so that security doesn't cost me convenience.
- As a **security administrator**, I want to know exactly which accounts and configurations are exposed to AiTM before an attacker finds them, so that I can fix the highest-risk gaps first.
- As a **security administrator**, I want every blocked attack explained in plain language with a clear reason, so that I can act on it without personally reconstructing cryptographic logs.
- As an **application owner**, I want KAAVAL enforced as deterministic policy, not a probabilistic score, so that I can defend a blocking decision to an auditor or a frustrated user.
- As a **judge**, I want to watch a real cookie theft fail in real time, not be told hypothetically that it would fail — this is a tension against the administrator's need for a calm, non-live dashboard, and the demo plan (§12 of the TRD) is what resolves it.

## 4. Scope

### 4.1 In scope

- WebAuthn/passkey login, extended to authorize a temporary, non-exportable, per-session browser key pair (**PulseLock**).
- Signed, canonicalized, replay-protected requests for every authenticated action after login (**PulseLock**).
- Deterministic, explainable identity-configuration exposure scoring against a simulated mock organization (**Radar**).
- Deterministic blocking of unrestricted device-code authentication and of OAuth consent grants that fail policy (**Guardian**).
- Plain-language, post-decision incident narration from structured security events (**Chronicle**).
- A genuine demo web application with both an unprotected (baseline) mode and a PulseLock-protected mode, plus a simulated attacker console, so the before/after can be shown live.
- A combined dashboard surfacing Radar findings, live blocked-attack events, an incident timeline, and Chronicle's explanations.

### 4.2 Out of scope

- **Behavioral biometrics and browser/canvas/font fingerprinting** — deliberately not used as a trust signal anywhere in the system; §1.4/§5.5 of the underlying design explicitly treat pattern-based signals as spoofable and therefore secondary at best, never a substitute for cryptographic proof.
- **Bluetooth or cellular-based routing/verification** — not part of the browser- and server-based trust model.
- **Network-trust scoring** — same reasoning as fingerprinting: it can change legitimately and can be imitated.
- **Email scanning and DNS comparison** — not part of the session-protection or authorization-policy problem being solved.
- **A native mobile application** — the MVP is web-only.
- **Autonomous remediation** — Guardian and PulseLock enforce policy deterministically at the moment of the request; nothing revokes access, changes configuration, or takes corrective action on its own initiative outside that request-time enforcement.
- **Full Microsoft 365 / enterprise identity-provider integration** — Radar's findings are demonstrated against a clearly labeled simulated organization, not a live tenant.
- **Redis or other distributed infrastructure** — not introduced unless demo load actually requires it; SQLite and in-process state are sufficient at MVP scale.
- **Protection against endpoint malware, a compromised genuine server, or an administrator who deliberately weakens policy** — stated explicitly as outside KAAVAL's trust boundary (see §14 of the TRD), not an oversight.

## 5. Functional Requirements

**PulseLock**

- FR-1: The system shall generate a non-exportable public/private key pair in the browser, scoped to a single session, at login time.
- FR-2: The system shall require WebAuthn passkey authentication, with the server challenge extended to also authorize the newly generated session public key.
- FR-3: The system shall bind the server-side session record to the authorized public key rather than treating the session cookie as a standalone bearer secret.
- FR-4: The system shall require every authenticated request to carry a signature over a canonical message containing: session ID, HTTP method, real origin, endpoint path, a hash of the request body, a server-issued nonce, a sequence number, and a timestamp.
- FR-5: The system shall reject any request where the session is inactive, the signature does not match the bound public key, the origin/method/endpoint/body-hash do not match what was actually received, the nonce has already been used, the sequence number is invalid, or the timestamp falls outside the permitted window.
- FR-6: The system shall log every rejected request with the specific reason for rejection.

**Radar**

- FR-7: The system shall evaluate a simulated organization's identity configuration against a fixed checklist: phishable MFA still active, passkeys available but unenforced, weak fallback capable of bypassing passkeys, unrestricted device-code authentication, unknown/unverified OAuth applications, excessive application permissions, unmonitored admin/break-glass accounts, Conditional Access exclusions, and long-lived or incompletely revocable sessions.
- FR-8: The system shall produce a numeric exposure score together with a list of findings, where every finding names the exact configuration issue it is based on.

**Guardian**

- FR-9: The system shall block device-code authentication by default, allowing it only for allowlisted applications on registered devices with short-lived, single-use codes, with administrator approval required for sensitive cases.
- FR-10: The system shall evaluate every new OAuth consent request against application/client identity, publisher verification, requested scopes, redirect URI, organizational allowlist status, and whether offline/persistent access is requested, and block any request that fails policy.
- FR-11: Guardian's authorization decisions shall be produced by deterministic policy; no probabilistic or LLM-based component shall be able to approve, deny, or otherwise alter an authorization decision.

**Chronicle**

- FR-12: The system shall convert a completed sequence of structured security events into a plain-language incident summary, after — never before — the underlying security decision has been made.
- FR-13: Chronicle shall be permitted to summarize, draft a report, and suggest deterministic remediation steps; it shall not be permitted to grant access, approve consent, or revoke a session.

**Demo/dashboard**

- FR-14: The system shall provide an unprotected baseline mode in which a captured session cookie can be successfully replayed, so the vulnerability being solved is demonstrable, not asserted.
- FR-15: The system shall provide a dashboard showing Radar findings, a live feed of blocked attack attempts, a chronological incident timeline, and Chronicle's explanations for each incident.

## 6. Non-Functional Requirements

| ID | Category | Requirement |
|---|---|---|
| NFR-1 | Security | Cryptographic proof-of-possession is the only mechanism that establishes request authenticity; supporting signals (new device, new country, impossible travel, etc.) may inform investigation or trigger step-up authentication but must never themselves be treated as proof of identity. |
| NFR-2 | Explainability | Every Radar finding, every Guardian block, and every PulseLock rejection must trace to one specific, named check or verification step — no opaque score or unexplained denial. |
| NFR-3 | Honesty of output | Chronicle's narratives must be grounded strictly in the structured event data it is given; it must not introduce facts, causes, or attributions the underlying events do not support. Quantitative Radar scores are estimates over a fixed checklist, not a certified audit, and must be labeled as such. |
| NFR-4 | Performance | Server-side proof verification must add no more than 100 ms median overhead per request in the local demo environment. |
| NFR-5 | Data handling | Radar's demonstration data must be clearly labeled as simulated; Chronicle must only ever receive redacted, structured event data, never raw credentials or full session material. |
| NFR-6 | Demo reliability | The live demo path must not depend on any third-party service whose uptime the team does not control, beyond the LLM call used by Chronicle, which must have a scripted, pre-verified fallback narrative if the call fails or is slow. |

## 7. Success Metrics

| Metric | Target |
|---|---|
| Rejection rate of test requests missing bound-key proof | 100% (controlled test suite) |
| Rejection rate of modified request bodies | 100% (controlled test suite) |
| Rejection rate of duplicate/replayed nonces | 100% (controlled test suite) |
| Median server-side proof-verification overhead | < 100 ms (local demo environment) |
| Baseline (unprotected) cookie replay | Succeeds — this is a required negative-control result, not a bug |
| PulseLock-protected cookie replay | Fails, with a logged, explainable reason |
| Malicious OAuth consent request in demo scenario | Blocked by Guardian with a stated policy reason |
| Incident explanation availability | Chronicle produces a plain-language explanation for 100% of demo-scripted incidents |

## 8. Assumptions

- The genuine application server is not itself compromised.
- The user's genuine browser is not fully controlled by malware.
- Passkeys are enforced without a weaker authentication fallback left active.
- Any application integrating KAAVAL adopts the browser SDK and server middleware; KAAVAL cannot protect a request path it isn't wired into.
- Private session keys are generated as non-exportable and remain protected by the browser's own security boundary.
- Team composition and tooling (below) are fixed for this build: three builders on Claude Code Pro, one on Codex (Plus plan).

## 9. Dependencies

| Dependency | Nature |
|---|---|
| WebAuthn/FIDO2 browser support | Platform capability the passkey flow depends on |
| Web Crypto API | Browser API used for non-exportable session key generation and signing |
| An LLM API | Used only by Chronicle, and only on already-redacted, structured event data |
| Mock organization dataset | Radar's demonstration input; must be clearly labeled simulated, not live tenant data |

## 10. Risks and Mitigations

| Risk | Mitigation |
|---|---|
| A live LLM call for Chronicle fails or is slow during the judged demo | Pre-verified, scripted fallback narrative for each demo-scripted incident; Chronicle's call is never on the critical path for PulseLock/Guardian's actual enforcement. |
| Judges or reviewers assume Chronicle's LLM is making security decisions | State explicitly, in the dashboard UI and in the pitch, that the security engine decides first and deterministically; the LLM only explains afterward and cannot grant, approve, or revoke anything. |
| A team member conflates "supporting risk signal" with "proof of identity" while building | NFR-1 and the operating contract in every build document state this as a hard rule, not a style preference. |
| Branch work drifts from the shared data contracts mid-build | Contracts are frozen in the TRD before build starts and copied verbatim into every build document; see the Team Integration Plan for the freeze point and merge order. |
| Radar's simulated data is mistaken for real organizational exposure | Dashboard UI and any published output explicitly labeled "simulated organization" per NFR-5. |
| Scope creep toward behavioral biometrics/fingerprinting mid-build, since it's a common instinct in this space | Explicitly listed as out of scope in §4.2 and in the operating contract's GROUND TRUTH section for every module — not to be silently reintroduced. |

## 11. Acceptance Criteria

1. ✅ A demo user can log into the unprotected application; the attacker console captures the session cookie and successfully replays it from a different browser profile.
2. ✅ The same user authenticates via passkey with PulseLock enabled; the attacker console captures the new cookie; replay from a different browser profile fails, with a logged reason.
3. ✅ A captured, legitimate signed request with a modified body is rejected because the body hash no longer matches.
4. ✅ A captured, legitimate signed request replayed unchanged is rejected because its nonce has already been used.
5. ✅ Radar produces an exposure score and a list of findings against the mock organization, each traceable to a named configuration issue.
6. ✅ An OAuth consent request with dangerous scopes from an unverified publisher is blocked by Guardian with a stated policy reason.
7. ✅ Chronicle produces a plain-language explanation of the blocked replay and the blocked OAuth grant, without having made either decision itself.
8. ✅ The dashboard displays Radar findings, the live blocked-attack feed, the incident timeline, and Chronicle's explanations in one place.
9. ✅ All four success-metric rejection rates (§7) read 100% in the controlled test suite, and median verification overhead is under 100 ms.

## 12. Glossary

- **AiTM (Adversary-in-the-Middle):** an attacker's server sits between victim and real site, relaying traffic live to capture credentials and session tokens in real time.
- **Bearer credential:** a secret that grants access to whoever simply possesses it, regardless of how it was obtained.
- **Proof-of-possession:** a credential model requiring active proof of control of a private key via a fresh signature, not just presentation of a copyable value.
- **WebAuthn / FIDO2 / Passkey:** a phishing-resistant login standard where the browser cryptographically binds authentication to the real site's exact origin.
- **Origin binding:** tying a cryptographic proof to a specific website domain so it cannot be reused on a look-alike domain.
- **Nonce:** a one-time random value preventing a captured message from being resent later.
- **Canonicalization:** formatting the data to be signed in one fixed, unambiguous structure so both parties compute the same signature input.
- **Device-code flow:** an OAuth mechanism for input-limited devices, misusable if a victim is tricked into entering an attacker-obtained code.
- **Consent phishing:** tricking a user into legitimately approving a malicious application's permission request.
- **Conditional Access:** identity-provider policy rules that are only effective if they apply universally; exclusions create gaps.
