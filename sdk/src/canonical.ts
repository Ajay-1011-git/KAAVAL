// T-AJ.4 — canonical string builder and signer, producing a
// SignedRequestEnvelope per TRD §6.1 / build-doc §B.2. This is the literal,
// frozen contract Rohith's gateway parses — field names, order, and the
// canonical string format must never be changed here without full-team
// agreement.
//
// Verified against MDN (SubtleCrypto.digest()) in-session: digest() takes
// ("SHA-256", data: BufferSource) and resolves an ArrayBuffer, converted to
// hex via the standard byte-to-hex-pad-join pattern (no reliance on the very
// new Uint8Array.prototype.toHex, for broad compatibility).

// Copied verbatim from TRD §6.1 — do not modify.
export interface SignedRequestEnvelope {
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

export interface EnvelopeInput {
  session_id: string;
  method: string;
  origin: string;
  path: string;
  /** Exact raw request body bytes (or the empty string for a bodyless request). */
  body: string | Uint8Array;
  nonce: string;
  sequence: number;
}

export type SignFn = (data: Uint8Array) => Promise<string>;

function bytesFromBody(body: string | Uint8Array): Uint8Array {
  return typeof body === "string" ? new TextEncoder().encode(body) : body;
}

async function sha256Hex(data: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", data as BufferSource);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Builds the exact canonical string to sign, in the fixed, frozen field
 * order — no other format is valid (TRD §6.1).
 */
export function buildCanonicalString(fields: {
  session_id: string;
  method: string;
  origin: string;
  path: string;
  body_hash: string;
  nonce: string;
  sequence: number;
  timestamp: string;
}): string {
  return [
    fields.session_id,
    fields.method,
    fields.origin,
    fields.path,
    fields.body_hash,
    fields.nonce,
    String(fields.sequence),
    fields.timestamp,
  ].join("\n");
}

/**
 * Computes body_hash, builds the canonical string, signs it with the
 * session's non-exportable private key, and returns the full
 * SignedRequestEnvelope.
 */
export async function buildEnvelope(input: EnvelopeInput, signFn: SignFn): Promise<SignedRequestEnvelope> {
  const body_hash = await sha256Hex(bytesFromBody(input.body));
  const timestamp = new Date().toISOString();

  const canonicalString = buildCanonicalString({
    session_id: input.session_id,
    method: input.method,
    origin: input.origin,
    path: input.path,
    body_hash,
    nonce: input.nonce,
    sequence: input.sequence,
    timestamp,
  });

  const signature = await signFn(new TextEncoder().encode(canonicalString));

  return {
    session_id: input.session_id,
    method: input.method,
    origin: input.origin,
    path: input.path,
    body_hash,
    nonce: input.nonce,
    sequence: input.sequence,
    timestamp,
    signature,
  };
}
