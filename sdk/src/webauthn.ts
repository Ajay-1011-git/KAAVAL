// T-AJ.2 — WebAuthn registration ceremony.
// T-AJ.3 — WebAuthn login ceremony + session-to-key binding.
//
// Verified against MDN (CredentialsContainer.create(),
// CredentialsContainer.get(), PublicKeyCredential,
// AuthenticatorAssertionResponse) in-session:
// - navigator.credentials.create({ publicKey }) options: challenge and
//   user.id must be BufferSource (we decode server-sent base64url strings
//   into Uint8Array before passing them in).
// - The resolved PublicKeyCredential exposes id (base64url string), rawId
//   (ArrayBuffer), type, and response.{clientDataJSON, attestationObject}
//   (both ArrayBuffer) — all binary fields must be base64url-encoded again
//   before they can travel as JSON to the server.
// - navigator.credentials.get({ publicKey }) options: challenge (BufferSource),
//   rpId (string), allowCredentials[].id (BufferSource), userVerification.
// - Its AuthenticatorAssertionResponse exposes authenticatorData,
//   clientDataJSON and signature (all ArrayBuffer) plus userHandle, which the
//   WebAuthn spec allows to be null (usernameless flows), so it is treated
//   as nullable here.
import { base64UrlDecode, base64UrlEncode } from "./base64url.js";
import type { KaavalSdkConfig } from "./config.js";
import { generateSessionKeyPair, type SessionKeyPair } from "./keys.js";

interface RegistrationOptionsResponse {
  challenge: string;
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: { type: "public-key"; alg: number }[];
  timeout?: number;
  attestation?: AttestationConveyancePreference;
}

export interface RegistrationResult {
  credentialId: string;
  keyPair: SessionKeyPair;
}

interface LoginOptionsResponse {
  challenge: string;
  rpId: string;
  allowCredentials?: { id: string; type: "public-key" }[];
  userVerification?: UserVerificationRequirement;
  timeout?: number;
}

/**
 * The session the server has bound to our session public key. Holding the
 * SessionKeyPair here is safe: it carries only a non-exportable CryptoKey
 * handle and a sign() closure, never exportable private key material.
 */
export interface ActiveSession {
  sessionId: string;
  keyPair: SessionKeyPair;
}

let activeSession: ActiveSession | null = null;

/** The current PulseLock-bound session, or null if login has not happened. */
export function getActiveSession(): ActiveSession | null {
  return activeSession;
}

/** Drops the in-memory session binding (logout / test reset). */
export function clearActiveSession(): void {
  activeSession = null;
}

async function postJson<T>(url: string, body: unknown): Promise<T> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    throw new Error(`KAAVAL SDK: POST ${url} failed with status ${res.status}`);
  }
  return (await res.json()) as T;
}

// Cross-realm-safe ArrayBuffer check: `instanceof ArrayBuffer` fails when
// the value was constructed against a different global (e.g. a test
// environment's separate realm), even though it's a real ArrayBuffer.
function isArrayBuffer(value: unknown): value is ArrayBuffer {
  return Object.prototype.toString.call(value) === "[object ArrayBuffer]";
}

function isPublicKeyCredential(value: unknown): value is PublicKeyCredential {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Record<string, unknown>;
  return (
    typeof candidate.id === "string" &&
    isArrayBuffer(candidate.rawId) &&
    typeof candidate.response === "object" &&
    candidate.response !== null
  );
}

/**
 * Drives the WebAuthn registration ceremony and submits the session public
 * key generated in this call alongside the attestation, per TRD §5.
 */
export async function registerPasskey(
  config: KaavalSdkConfig,
  username: string,
): Promise<RegistrationResult> {
  const beginUrl = `${config.gatewayOrigin}/auth/webauthn/register/begin`;
  const options = await postJson<RegistrationOptionsResponse>(beginUrl, { username });

  if (options.rp.id !== config.relyingPartyId) {
    throw new Error(
      `KAAVAL SDK: server RP ID "${options.rp.id}" does not match configured relyingPartyId "${config.relyingPartyId}"`,
    );
  }

  const publicKey: PublicKeyCredentialCreationOptions = {
    challenge: base64UrlDecode(options.challenge) as BufferSource,
    rp: options.rp,
    user: {
      id: base64UrlDecode(options.user.id) as BufferSource,
      name: options.user.name,
      displayName: options.user.displayName,
    },
    pubKeyCredParams: options.pubKeyCredParams,
    timeout: options.timeout,
    attestation: options.attestation,
  };

  const credential = await navigator.credentials.create({ publicKey });
  if (!isPublicKeyCredential(credential)) {
    throw new Error("KAAVAL SDK: WebAuthn registration ceremony did not return a public-key credential");
  }

  const attestationResponse = credential.response as AuthenticatorAttestationResponse;
  if (
    !isArrayBuffer(attestationResponse.clientDataJSON) ||
    !isArrayBuffer(attestationResponse.attestationObject)
  ) {
    throw new Error("KAAVAL SDK: malformed attestation response from authenticator");
  }

  const keyPair = await generateSessionKeyPair();

  // Field names are the gateway's (backend/gateway/webauthn_routes.py), which
  // takes py_webauthn's own RegistrationResponseJSON shape. TRD §5's
  // anti-hallucination note makes these library-driven rather than frozen, so
  // the client conforms to the server that actually verifies them.
  const finishUrl = `${config.gatewayOrigin}/auth/webauthn/register/finish`;
  const finishResult = await postJson<{ verified: boolean; credential_id: string }>(finishUrl, {
    username,
    credential: {
      id: credential.id,
      rawId: base64UrlEncode(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: base64UrlEncode(attestationResponse.clientDataJSON),
        attestationObject: base64UrlEncode(attestationResponse.attestationObject),
      },
    },
    session_public_key: keyPair.publicKeyJwk,
  });

  if (typeof finishResult.credential_id !== "string" || finishResult.credential_id.length === 0) {
    throw new Error("KAAVAL SDK: register/finish did not return a credential_id");
  }

  return { credentialId: finishResult.credential_id, keyPair };
}

/**
 * Drives the WebAuthn login ceremony, submits a freshly generated session
 * public key to be bound to the new session, and stores the returned
 * session_id. The returned session is what makes every later request
 * provable rather than bearer-authenticated (PRD FR-2, FR-3).
 */
export async function loginWithPasskey(
  config: KaavalSdkConfig,
  username: string,
): Promise<string> {
  const beginUrl = `${config.gatewayOrigin}/auth/webauthn/login/begin`;
  const options = await postJson<LoginOptionsResponse>(beginUrl, { username });

  if (typeof options.challenge !== "string" || typeof options.rpId !== "string") {
    throw new Error("KAAVAL SDK: malformed login options from server");
  }
  if (options.rpId !== config.relyingPartyId) {
    throw new Error(
      `KAAVAL SDK: server RP ID "${options.rpId}" does not match configured relyingPartyId "${config.relyingPartyId}"`,
    );
  }

  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge: base64UrlDecode(options.challenge) as BufferSource,
    rpId: options.rpId,
    allowCredentials: (options.allowCredentials ?? []).map((credential) => ({
      id: base64UrlDecode(credential.id) as BufferSource,
      type: credential.type,
    })),
    userVerification: options.userVerification,
    timeout: options.timeout,
  };

  const credential = await navigator.credentials.get({ publicKey });
  if (!isPublicKeyCredential(credential)) {
    throw new Error("KAAVAL SDK: WebAuthn login ceremony did not return a public-key credential");
  }

  const assertionResponse = credential.response as AuthenticatorAssertionResponse;
  if (
    !isArrayBuffer(assertionResponse.clientDataJSON) ||
    !isArrayBuffer(assertionResponse.authenticatorData) ||
    !isArrayBuffer(assertionResponse.signature)
  ) {
    throw new Error("KAAVAL SDK: malformed assertion response from authenticator");
  }

  const keyPair = await generateSessionKeyPair();

  const finishUrl = `${config.gatewayOrigin}/auth/webauthn/login/finish`;
  const finishResult = await postJson<{ session_id: string }>(finishUrl, {
    username,
    credential: {
      id: credential.id,
      rawId: base64UrlEncode(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: base64UrlEncode(assertionResponse.clientDataJSON),
        authenticatorData: base64UrlEncode(assertionResponse.authenticatorData),
        signature: base64UrlEncode(assertionResponse.signature),
        // userHandle is nullable per the WebAuthn spec (usernameless flows).
        userHandle: isArrayBuffer(assertionResponse.userHandle)
          ? base64UrlEncode(assertionResponse.userHandle)
          : null,
      },
    },
    session_public_key: keyPair.publicKeyJwk,
  });

  if (typeof finishResult.session_id !== "string" || finishResult.session_id.length === 0) {
    throw new Error("KAAVAL SDK: login/finish did not return a session_id");
  }

  activeSession = { sessionId: finishResult.session_id, keyPair };
  return finishResult.session_id;
}
