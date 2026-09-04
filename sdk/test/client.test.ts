// @vitest-environment jsdom
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { createMockServer } from "../mock-server/index.js";
import { base64UrlDecode, base64UrlEncode } from "../src/base64url.js";
import { KaavalNoActiveSessionError, kaavalFetch, resetSequenceCounters } from "../src/client.js";
import type { KaavalSdkConfig } from "../src/config.js";
import { clearActiveSession, loginWithPasskey } from "../src/webauthn.js";

function stubAuthenticator(): void {
  const create = vi.fn();
  const get = vi.fn(async (options: CredentialRequestOptions) => {
    const publicKey = options.publicKey;
    if (!publicKey) throw new Error("expected publicKey options");
    const challengeB64Url = base64UrlEncode(publicKey.challenge as ArrayBuffer);
    const clientData = JSON.stringify({
      type: "webauthn.get",
      challenge: challengeB64Url,
      origin: "https://kaaval-demo.local",
    });
    return {
      id: "fake-credential-id",
      rawId: base64UrlDecode("fake-credential-id").buffer,
      type: "public-key",
      response: {
        clientDataJSON: new TextEncoder().encode(clientData).buffer,
        authenticatorData: new Uint8Array([9, 8, 7, 6]).buffer,
        signature: new Uint8Array([5, 4, 3, 2]).buffer,
        userHandle: null,
      },
    };
  });
  Object.defineProperty(globalThis.navigator, "credentials", {
    value: { create, get },
    configurable: true,
  });
}

describe("kaavalFetch", () => {
  let mockServer: ReturnType<typeof createMockServer>;
  let config: KaavalSdkConfig;

  beforeAll(async () => {
    mockServer = createMockServer();
    const gatewayOrigin = await mockServer.listen();
    config = { relyingPartyId: "kaaval-demo.local", gatewayOrigin };
    stubAuthenticator();
  });

  afterEach(() => {
    clearActiveSession();
    resetSequenceCounters();
    mockServer.state.receivedProofEnvelopes.length = 0;
  });

  afterAll(async () => {
    await mockServer.close();
  });

  it("throws a typed error when no session is active", async () => {
    await expect(kaavalFetch(config, "/api/transfer", { method: "POST", body: "{}" })).rejects.toThrow(
      KaavalNoActiveSessionError,
    );
  });

  it("attaches a valid, decodable X-KAAVAL-Proof header the mock server can decode back into the envelope", async () => {
    await loginWithPasskey(config);

    const response = await kaavalFetch(config, "/api/transfer", {
      method: "POST",
      body: JSON.stringify({ amount: 42 }),
    });
    expect(response.ok).toBe(true);
    const responseBody = (await response.json()) as { hadProof: boolean; path: string; method: string };
    expect(responseBody.hadProof).toBe(true);
    expect(responseBody.path).toBe("/api/transfer");
    expect(responseBody.method).toBe("POST");

    expect(mockServer.state.receivedProofEnvelopes).toHaveLength(1);
    const decoded = mockServer.state.receivedProofEnvelopes[0]!;
    expect(decoded.method).toBe("POST");
    expect(decoded.path).toBe("/api/transfer");
    expect(decoded.origin).toBe(config.gatewayOrigin);
    expect(decoded.sequence).toBe(1);
    expect(typeof decoded.signature).toBe("string");
    expect(decoded.signature.length).toBeGreaterThan(0);
  });

  it("increments sequence strictly for each subsequent request in the same session", async () => {
    await loginWithPasskey(config);

    await kaavalFetch(config, "/api/one", { method: "POST", body: "{}" });
    await kaavalFetch(config, "/api/two", { method: "POST", body: "{}" });
    await kaavalFetch(config, "/api/three", { method: "POST", body: "{}" });

    const sequences = mockServer.state.receivedProofEnvelopes.map((e) => e.sequence);
    expect(sequences).toEqual([1, 2, 3]);
  });

  it("uses a fresh nonce for every request", async () => {
    await loginWithPasskey(config);

    await kaavalFetch(config, "/api/a", { method: "POST", body: "{}" });
    await kaavalFetch(config, "/api/b", { method: "POST", body: "{}" });

    const nonces = mockServer.state.receivedProofEnvelopes.map((e) => e.nonce);
    expect(new Set(nonces).size).toBe(nonces.length);
  });

  // T-AJ.7 — sequence robustness under concurrency.
  it("assigns unique, strictly increasing sequence numbers to concurrent requests", async () => {
    await loginWithPasskey(config);

    const concurrentCount = 12;
    await Promise.all(
      Array.from({ length: concurrentCount }, (_unused, index) =>
        kaavalFetch(config, `/api/concurrent-${index}`, { method: "POST", body: "{}" }),
      ),
    );

    const sequences = mockServer.state.receivedProofEnvelopes.map((e) => e.sequence);
    expect(sequences).toHaveLength(concurrentCount);

    // No duplicates and no skipped numbers.
    expect(new Set(sequences).size).toBe(concurrentCount);
    expect([...sequences].sort((a, b) => a - b)).toEqual(
      Array.from({ length: concurrentCount }, (_unused, index) => index + 1),
    );

    // Dispatched in sequence order, so the gateway's strictly-increasing
    // check sees them in order rather than as stale replays.
    expect(sequences).toEqual([...sequences].sort((a, b) => a - b));
  });

  // The discriminating test for T-AJ.7. Plain uniqueness is not enough to
  // prove serialization: JS is single-threaded, so the read-modify-write in
  // nextSequence() cannot interleave and sequence numbers are unique even
  // with no lock at all. What the lock actually buys is that sequence
  // assignment follows the order calls were *made*, rather than the order
  // their nonce responses happened to land. Inverting nonce latency makes
  // that difference observable: without serialization the last caller wins
  // sequence 1.
  it("assigns sequence numbers in caller order even when nonce latency is inverted", async () => {
    await loginWithPasskey(config);

    const realFetch = globalThis.fetch;
    const concurrentCount = 6;
    let nonceCallIndex = 0;

    const fetchStub = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.endsWith("/auth/nonce")) {
        const delayMs = (concurrentCount - nonceCallIndex) * 20;
        nonceCallIndex += 1;
        await new Promise((resolve) => setTimeout(resolve, delayMs));
      }
      return realFetch(input, init);
    };
    globalThis.fetch = fetchStub as typeof globalThis.fetch;

    try {
      await Promise.all(
        Array.from({ length: concurrentCount }, (_unused, index) =>
          kaavalFetch(config, `/api/ordered-${index}`, { method: "POST", body: "{}" }),
        ),
      );
    } finally {
      globalThis.fetch = realFetch;
    }

    const envelopes = mockServer.state.receivedProofEnvelopes;
    expect(envelopes).toHaveLength(concurrentCount);

    for (const envelope of envelopes) {
      const callerIndex = Number(envelope.path.replace("/api/ordered-", ""));
      expect(envelope.sequence).toBe(callerIndex + 1);
    }
  });

  it("issues a distinct nonce to every concurrent request", async () => {
    await loginWithPasskey(config);

    const concurrentCount = 12;
    await Promise.all(
      Array.from({ length: concurrentCount }, (_unused, index) =>
        kaavalFetch(config, `/api/nonce-${index}`, { method: "POST", body: "{}" }),
      ),
    );

    const nonces = mockServer.state.receivedProofEnvelopes.map((e) => e.nonce);
    expect(new Set(nonces).size).toBe(concurrentCount);
  });

  // Regression: btoa() over UTF-16 code units silently corrupts Latin-1
  // characters and throws above them, so the proof header must be UTF-8
  // encoded before base64. The mock server decodes it exactly as the
  // Python gateway would (base64 -> utf-8 -> JSON.parse).
  it("encodes a non-ASCII path in the proof header without corrupting it", async () => {
    await loginWithPasskey(config);

    const unicodePath = "/api/café-転送";
    const response = await kaavalFetch(config, unicodePath, { method: "POST", body: "{}" });
    expect(response.ok).toBe(true);

    const decoded = mockServer.state.receivedProofEnvelopes[0]!;
    expect(decoded.path).toBe(unicodePath);
  });
});
