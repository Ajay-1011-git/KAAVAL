// T-AJ.5 — SDK fetch wrapper. Transparently fetches a fresh nonce, builds
// and signs the SignedRequestEnvelope (§B.2 / canonical.ts), and attaches it
// as the X-KAAVAL-Proof header before making the real request. This is the
// single call site the rest of a demo app should use for any protected
// request — it is what turns "has a cookie" back into "proved possession of
// the bound key, just now, for exactly this request."
import { buildEnvelope } from "./canonical.js";
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

function base64Encode(value: string): string {
  return btoa(value);
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
  const nonce = await fetchNonce(config, session.sessionId);
  const sequence = nextSequence(session.sessionId);

  const envelope = await buildEnvelope(
    {
      session_id: session.sessionId,
      method,
      origin: config.gatewayOrigin,
      path,
      body,
      nonce,
      sequence,
    },
    session.keyPair.sign,
  );

  const headers = new Headers(options.headers);
  headers.set("X-KAAVAL-Proof", base64Encode(JSON.stringify(envelope)));

  return fetch(`${config.gatewayOrigin}${path}`, {
    ...options,
    method,
    headers,
    body: body.length > 0 ? (body as BodyInit) : undefined,
  });
}
