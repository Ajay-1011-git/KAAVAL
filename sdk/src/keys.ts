// T-AJ.1 — non-exportable per-session ECDSA P-256 key pair generation.
//
// Verified against MDN (SubtleCrypto.generateKey, SubtleCrypto.sign) in-session:
// - generateKey algorithm: { name: "ECDSA", namedCurve: "P-256" }
// - sign algorithm: { name: "ECDSA", hash: { name: "SHA-256" } }
// - sign() returns the raw IEEE P1363 (r || s) signature, not DER.
// - The `extractable` flag on generateKey only governs the private key;
//   the public key is always exportable regardless of that flag.

export interface SessionKeyPair {
  /** The session's public key, exported as JWK so it can be sent to the server. */
  publicKeyJwk: JsonWebKey;
  /** Signs arbitrary bytes with the non-exportable private key. Returns a base64 signature. */
  sign(data: Uint8Array): Promise<string>;
  /**
   * The opaque private key handle, exposed only so callers/tests can confirm
   * `extractable === false`. The handle carries no accessible key material —
   * `exportKey`/`wrapKey` throw for a non-extractable CryptoKey.
   */
  privateKey: CryptoKey;
}

function bufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

/**
 * Generates a per-session ECDSA P-256 key pair via Web Crypto.
 * The private key is generated with extractable: false, so it can never
 * leave the browser's own secure boundary — this is the literal property
 * PulseLock's proof-of-possession model depends on.
 */
export async function generateSessionKeyPair(): Promise<SessionKeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "ECDSA",
      namedCurve: "P-256",
    },
    false,
    ["sign", "verify"],
  );

  const { publicKey, privateKey } = keyPair as CryptoKeyPair;

  const publicKeyJwk = await crypto.subtle.exportKey("jwk", publicKey);

  const sign = async (data: Uint8Array): Promise<string> => {
    const signature = await crypto.subtle.sign(
      {
        name: "ECDSA",
        hash: { name: "SHA-256" },
      },
      privateKey,
      data as BufferSource,
    );
    return bufferToBase64(signature);
  };

  return { publicKeyJwk, sign, privateKey };
}
