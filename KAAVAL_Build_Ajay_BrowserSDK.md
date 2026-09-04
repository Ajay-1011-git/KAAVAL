# BROWSER SDK — Complete Build Instructions
### Drift-proof, hallucination-resistant prompts aligned to KAAVAL_PRD.md and KAAVAL_TRD.md

> **Purpose.** Build the browser-side half of PulseLock: WebAuthn passkey ceremonies, non-exportable session key generation, and the request canonicalizer/signer that produces the `SignedRequestEnvelope` every protected request must carry.
>
> **Alignment guarantee.** If anything here conflicts with `KAAVAL_PRD.md` or `KAAVAL_TRD.md`, those documents win. If you notice a conflict, stop and flag it rather than silently picking one.
>
> **Partner module note.** This is one of four parallel modules. Rohith's `feature/gateway-core` is the server this SDK talks to. You do not need Rohith's actual running server to finish or verify your tasks — build and test against a local mock server that implements exactly the contract in §B.2, matching TRD §5's endpoint list. Do not touch anything under `backend/` or `frontend/`.

---

# §A. Operating Contract — paste into CLAUDE.md

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

---

# §B. Canonical Specifications

## B.1 Environment / config

The SDK takes an init config object (not env vars, since it's a browser package):
```typescript
interface KaavalSdkConfig {
  relyingPartyId: string;   // e.g. "kaaval-demo.local" — must match the server's WebAuthn RP ID exactly, verify with Rohith's actual config before hardcoding a value
  gatewayOrigin: string;    // e.g. "https://kaaval-demo.local"
}
```

## B.2 Data contracts (copied verbatim from TRD §6.1 — do not modify)

```typescript
interface SignedRequestEnvelope {
  session_id: string;
  method: string;
  origin: string;
  path: string;
  body_hash: string;
  nonce: string;
  sequence: number;
  timestamp: string;
  signature: string;
}
```
Canonical string to sign, fixed order, newline-joined:
```text
session_id\nmethod\norigin\npath\nbody_hash\nnonce\nsequence\ntimestamp
```
Transport: sent as header `X-KAAVAL-Proof`, value = `base64(JSON.stringify(envelope))`.

Server endpoints you call (TRD §5) — verify the real request/response body shape of the WebAuthn `begin`/`finish` pair against whatever library Rohith confirms server-side, but the purpose of each is fixed:
- `POST /auth/webauthn/register/begin` → returns WebAuthn creation options
- `POST /auth/webauthn/register/finish` → you send the attestation response **plus** the new session public key; server returns confirmation
- `POST /auth/webauthn/login/begin` → returns WebAuthn request options
- `POST /auth/webauthn/login/finish` → you send the assertion response plus the session public key to be bound; server returns `{ session_id }`
- `POST /auth/nonce` → returns `{ nonce: string, issued_at: string }`, call this immediately before signing each state-changing request

## B.3 File/folder structure

```text
sdk/
  src/
    keys.ts          # T-AJ.1 — non-exportable key pair generation
    webauthn.ts       # T-AJ.2, T-AJ.3 — registration + login ceremonies
    canonical.ts       # T-AJ.4 — canonical string builder + signer
    client.ts          # T-AJ.5 — fetch wrapper, nonce fetch, header attach
    indicator.ts        # T-AJ.6 — protection-state UI widget
  test/
    canonical.test.ts
    client.test.ts
  mock-server/
    index.ts            # local mock implementing §B.2's endpoints, for standalone verification
```

---

# §C. Tasks

## T-AJ.1 · Non-exportable session key generation — `sdk/src/keys.ts` · P0 · depends: none

> **PROMPT**
> Goal: generate a per-session ECDSA (P-256) key pair via Web Crypto, with the private key non-exportable, and expose a function to sign an arbitrary byte string with it.
> Files you may touch: `sdk/src/keys.ts`, `sdk/test/keys.test.ts`.
> Requirements: `generateSessionKeyPair()` returns `{ publicKeyJwk, sign(data: Uint8Array): Promise<string> }` where `sign` returns a base64 signature. The private `CryptoKey` must be generated with `extractable: false`. Before writing the `generateKey`/`sign`/`exportKey` calls, verify the exact current Web Crypto API parameter shapes for ECDSA P-256 on MDN in this session — do not write them from memory.
> **VERIFY:** run the test suite (`npm test -- keys.test.ts`) and paste real output showing a key pair is generated, the public key is exportable, and attempting to export the private key throws.

## T-AJ.2 · WebAuthn registration ceremony — `sdk/src/webauthn.ts` · P0 · depends: T-AJ.1

> **PROMPT**
> Goal: drive the WebAuthn registration ceremony and submit the session public key from T-AJ.1 alongside it, per TRD §5.
> Files you may touch: `sdk/src/webauthn.ts`, `sdk/test/webauthn.test.ts`.
> Requirements: `registerPasskey(config: KaavalSdkConfig)` calls `POST /auth/webauthn/register/begin`, passes the result into `navigator.credentials.create()`, then calls `POST /auth/webauthn/register/finish` with the attestation response and the session public key. Verify the real current shape of `navigator.credentials.create()`'s `publicKey` options and the `PublicKeyCredential` response object on MDN in this session before coding this — do not guess field names.
> **VERIFY:** run against `sdk/mock-server` (build this alongside if it doesn't exist yet — implement `/auth/webauthn/register/begin` and `/finish` per B.2's *purpose*, using placeholder challenge/response data, not a real WebAuthn library) and paste real console output showing the ceremony completes and the mock server receives the session public key.

## T-AJ.3 · WebAuthn login + session binding — `sdk/src/webauthn.ts` · P0 · depends: T-AJ.1, T-AJ.2

> **PROMPT**
> Goal: drive the WebAuthn login ceremony, submit the session public key to be bound, and store the resulting `session_id`.
> Files you may touch: `sdk/src/webauthn.ts`, `sdk/test/webauthn.test.ts`.
> Requirements: `loginWithPasskey(config)` calls `/auth/webauthn/login/begin`, calls `navigator.credentials.get()`, then `/auth/webauthn/login/finish` with the assertion plus session public key, and returns the `session_id` from the response. Same anti-hallucination note as T-AJ.2 applies to `navigator.credentials.get()`.
> **VERIFY:** paste real output from the mock server showing a `session_id` is returned and stored.

## T-AJ.4 · Canonicalizer and signer — `sdk/src/canonical.ts` · P0 · depends: T-AJ.1

> **PROMPT**
> Goal: implement the exact canonical string builder and produce a signed `SignedRequestEnvelope` per §B.2.
> Files you may touch: `sdk/src/canonical.ts`, `sdk/test/canonical.test.ts`.
> Requirements: `buildEnvelope({session_id, method, origin, path, body, nonce, sequence}, signFn)` — computes `body_hash` as hex SHA-256 of the exact raw body bytes (use `crypto.subtle.digest("SHA-256", ...)`, verify the exact API call shape on MDN before writing it), builds the canonical string in the fixed field order from §B.2, signs it with the key from T-AJ.1, and returns the full `SignedRequestEnvelope` including `timestamp` as ISO-8601 UTC.
> **VERIFY:** unit test asserting the canonical string is built in the exact fixed order, and that changing any one field (e.g. `path`) changes the resulting signature. Paste real test output.

## T-AJ.5 · SDK fetch wrapper — `sdk/src/client.ts` · P0 · depends: T-AJ.3, T-AJ.4

> **PROMPT**
> Goal: a `kaavalFetch(url, options)` wrapper that transparently fetches a fresh nonce, builds and signs the envelope, and attaches it as the `X-KAAVAL-Proof` header before making the real request.
> Files you may touch: `sdk/src/client.ts`, `sdk/test/client.test.ts`.
> Requirements: before every state-changing request, call `POST /auth/nonce`, then build the envelope via T-AJ.4, base64-encode it, and set `X-KAAVAL-Proof`. Track and increment `sequence` per session in memory. If no active session exists, throw a clear, typed error rather than silently sending an unsigned request.
> **VERIFY:** against the mock server, paste real output showing a request made through `kaavalFetch` carries a valid `X-KAAVAL-Proof` header and the mock server can decode it back into the original envelope fields.

## T-AJ.6 · Protection-state indicator — `sdk/src/indicator.ts` · P1 · depends: T-AJ.3

> **PROMPT**
> Goal: a small, framework-agnostic UI widget showing whether the current session is PulseLock-protected (bound to a signing key) or not, for the demo's visual "before/after" moment.
> Files you may touch: `sdk/src/indicator.ts`.
> Requirements: renders a small fixed element (plain DOM API, no framework dependency) showing "Protected" with the bound key's short fingerprint when a session exists, "Not protected" otherwise. No network calls of its own — reads state from `client.ts`.
> **VERIFY:** manual check pasted as a screenshot description or DOM snapshot showing both states render correctly.

## T-AJ.7 · Multi-request sequence robustness — `sdk/src/client.ts` · P2 · depends: T-AJ.5

> **PROMPT**
> Goal: ensure `sequence` tracking is correct even if two requests are in flight concurrently (no duplicate or skipped sequence numbers).
> Files you may touch: `sdk/src/client.ts`, `sdk/test/client.test.ts`.
> Requirements: serialize sequence-number assignment (e.g. a simple in-memory queue/lock) so concurrent `kaavalFetch` calls never reuse a sequence number.
> **VERIFY:** test firing multiple concurrent `kaavalFetch` calls and asserting all sequence numbers are unique and strictly increasing; paste real output.

---

# §D. Build order

| Window | Tasks | Expected outcome |
|---|---|---|
| Day 1, hrs 0-3 | T-AJ.1 | Non-exportable key generation works and is tested. |
| Day 1, hrs 3-7 | T-AJ.2, T-AJ.3 | Full WebAuthn registration + login ceremony works against the mock server. |
| Day 1, hrs 7-10 | T-AJ.4 | Canonical envelope building and signing is correct and tested. |
| Day 2, hrs 0-3 | T-AJ.5 | SDK fetch wrapper attaches valid signed envelopes automatically. |
| Day 2, hrs 3-5 | T-AJ.6 | Protection-state indicator renders both states. |
| Day 2, hrs 5-7 | Integration with Rohith's real gateway (post-merge) | Real login + real signed request succeed against the real server. |
| Day 2, hrs 7-8 | T-AJ.7 (if time remains) | Sequence robustness under concurrency. |

---

# §E. Final acceptance

1. ✅ `generateSessionKeyPair()` produces a non-exportable private key (T-AJ.1's VERIFY).
2. ✅ Registration and login ceremonies complete against the mock server and submit the session public key (T-AJ.2, T-AJ.3).
3. ✅ The canonical string is built in the exact fixed field order and signatures change when any field changes (T-AJ.4).
4. ✅ `kaavalFetch` attaches a valid, decodable `X-KAAVAL-Proof` header to every request (T-AJ.5).
5. ✅ The protection-state indicator correctly shows protected/unprotected (T-AJ.6).
6. ✅ No private key material ever appears in a log, variable dump, or network payload.
7. ✅ Only files under `sdk/` were touched; `backend/contracts.py`'s shape was never modified.
