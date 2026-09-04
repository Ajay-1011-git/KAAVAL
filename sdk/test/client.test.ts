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
});
