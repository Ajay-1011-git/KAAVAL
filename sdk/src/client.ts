// T-AJ.5 — SDK fetch wrapper. Transparently fetches a fresh nonce, builds
// and signs the SignedRequestEnvelope (§B.2 / canonical.ts), and attaches it
// as the X-KAAVAL-Proof header before making the real request. This is the
// single call site the rest of a demo app should use for any protected
// request — it is what turns "has a cookie" back into "proved possession of
// the bound key, just now, for exactly this request."
import { buildEnvelope, type SignedRequestEnvelope } from "./canonical.js";
import type { KaavalSdkConfig } from "./config.js";
import { getActiveSession } from "./webauthn.js";

// T-AJ.6's indicator reads session state through this module, per its spec
// ("reads state from client.ts") — re-exported here rather than duplicated,
// since webauthn.ts (T-AJ.3) is the single source of truth for the active
// session.
export { getActiveSession, clearActiveSession, type ActiveSession } from "./webauthn.js";

export class KaavalNoActiveSessionError extends Error {
  constructor() {
    super("KAAVAL SDK: no active PulseLock session — call loginWithPasskey() first");
    this.name = "KaavalNoActiveSessionError";
  }
}

interface NonceResponse {
  nonce: string;
  issued_at: string;
}

export interface KaavalFetchOptions extends Omit<RequestInit, "body"> {
  /** Exact raw request body bytes. Omit for a bodyless request. */
  body?: string | Uint8Array;
}

// One monotonic sequence counter per session_id, kept in memory for the
// life of the page per TRD §6.1's "strictly increasing per session" rule.
const sequenceCounters = new Map<string, number>();

function nextSequence(sessionId: string): number {
  const next = (sequenceCounters.get(sessionId) ?? 0) + 1;
  sequenceCounters.set(sessionId, next);
  return next;
}

/** Test-only reset so sequence numbers don't leak state across test cases. */
export function resetSequenceCounters(): void {
  sequenceCounters.clear();
}

async function fetchNonce(config: KaavalSdkConfig, sessionId: string): Promise<string> {
  const nonceUrl = `${config.gatewayOrigin}/auth/nonce`;
  const res = await fetch(nonceUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ session_id: sessionId }),
  });
  if (!res.ok) {
    throw new Error(`KAAVAL SDK: POST ${nonceUrl} failed with status ${res.status}`);
  }
  const body = (await res.json()) as NonceResponse;
  if (typeof body.nonce !== "string" || body.nonce.length === 0) {
    throw new Error("KAAVAL SDK: /auth/nonce did not return a nonce");
  }
  return body.nonce;
}

/**
 * base64(JSON.stringify(envelope)) per §B.2 — encoding the JSON as UTF-8
 * bytes first.
 *
 * A bare btoa() operates on UTF-16 code units, which breaks in two ways the
 * moment any envelope field (realistically `path`) carries a non-ASCII
 * character: for Latin-1 characters it silently emits the wrong bytes
 * (U+00E9 as 0xE9 rather than UTF-8's 0xC3 0xA9), so the gateway's
 * base64-decode-then-UTF-8-decode yields mojibake while body_hash was
 * computed over correct UTF-8; and above Latin-1 it throws
 * InvalidCharacterError outright. Encoding to UTF-8 first is what the
 * gateway's b64decode(...).decode("utf-8") expects.
 */
function encodeProofHeader(envelope: SignedRequestEnvelope): string {
  const utf8Bytes = new TextEncoder().encode(JSON.stringify(envelope));
  let binary = "";
  for (const byte of utf8Bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

// Serializes nonce fetch -> sequence assignment -> signing -> dispatch, so
// concurrent kaavalFetch calls can never be assigned the same sequence
// number or dispatch out of sequence order (T-AJ.7). The lock is released
// once fetch() has been *called*, not once the server responds, so requests
// still overlap on the wire rather than being fully serialized.
//
// Note for gateway integration: this guarantees in-order *dispatch*. Final
// arrival order is still subject to network/HTTP-2 reordering, so whether
// the gateway's strictly-increasing sequence check tolerates out-of-order
// arrival is a question for the gateway owner, not something the SDK can
// guarantee alone.
let dispatchChain: Promise<unknown> = Promise.resolve();

function withDispatchLock<T>(task: () => Promise<T>): Promise<T> {
  const result = dispatchChain.then(task, task);
  // Keep the chain alive even when a task rejects, so one failed request
  // cannot deadlock every later one.
  dispatchChain = result.then(
    () => undefined,
    () => undefined,
  );
  return result;
}

/**
 * Fetches a fresh nonce, builds and signs a SignedRequestEnvelope for this
 * exact request, attaches it as X-KAAVAL-Proof, and performs the request.
 * Throws KaavalNoActiveSessionError rather than silently sending an
 * unsigned request if no session is bound yet.
 */
export async function kaavalFetch(
  config: KaavalSdkConfig,
  path: string,
  options: KaavalFetchOptions = {},
): Promise<Response> {
  const session = getActiveSession();
  if (!session) {
    throw new KaavalNoActiveSessionError();
  }

  const method = (options.method ?? "GET").toUpperCase();
  const body = options.body ?? "";

  // The whole nonce -> sequence -> sign -> dispatch chain runs under the
  // lock, so sequence numbers are assigned and sent in the same order.
  // The Response promise is returned wrapped, so awaiting the locked task
  // does not wait on the server's response and hold the lock open.
  const dispatched = await withDispatchLock(async () => {
    const nonce = await fetchNonce(config, session.sessionId);
    const sequence = nextSequence(session.sessionId);

    const envelope = await buildEnvelope(
      {
        session_id: session.sessionId,
        method,
        // The gateway's configured origin, not window.location.origin: the
        // server compares this asserted value against the Origin header the
        // browser itself sets and the page cannot forge, so a page served
        // from an attacker's domain cannot produce a matching pair.
        origin: config.gatewayOrigin,
        path,
        body,
        nonce,
        sequence,
      },
      session.keyPair.sign,
    );

    const headers = new Headers(options.headers);
    headers.set("X-KAAVAL-Proof", encodeProofHeader(envelope));

    return {
      response: fetch(`${config.gatewayOrigin}${path}`, {
        ...options,
        method,
        headers,
        body: body.length > 0 ? (body as BodyInit) : undefined,
      }),
    };
  });

  return dispatched.response;
}
