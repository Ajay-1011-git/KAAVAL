// T-AJ.2 — WebAuthn registration ceremony.
//
// Verified against MDN (CredentialsContainer.create(), PublicKeyCredential)
// in-session:
// - navigator.credentials.create({ publicKey }) options: challenge and
//   user.id must be BufferSource (we decode server-sent base64url strings
//   into Uint8Array before passing them in).
// - The resolved PublicKeyCredential exposes id (base64url string), rawId
//   (ArrayBuffer), type, and response.{clientDataJSON, attestationObject}
//   (both ArrayBuffer) — all binary fields must be base64url-encoded again
//   before they can travel as JSON to the server.
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
export async function registerPasskey(config: KaavalSdkConfig): Promise<RegistrationResult> {
  const beginUrl = `${config.gatewayOrigin}/auth/webauthn/register/begin`;
  const options = await postJson<RegistrationOptionsResponse>(beginUrl, {});

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

  const finishUrl = `${config.gatewayOrigin}/auth/webauthn/register/finish`;
  const finishResult = await postJson<{ credentialId: string }>(finishUrl, {
    attestationResponse: {
      id: credential.id,
      rawId: base64UrlEncode(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: base64UrlEncode(attestationResponse.clientDataJSON),
        attestationObject: base64UrlEncode(attestationResponse.attestationObject),
      },
    },
    sessionPublicKeyJwk: keyPair.publicKeyJwk,
  });

  return { credentialId: finishResult.credentialId, keyPair };
}
