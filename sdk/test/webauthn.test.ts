// @vitest-environment jsdom
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createMockServer, type MockServerState } from "../mock-server/index.js";
import { base64UrlDecode, base64UrlEncode } from "../src/base64url.js";
import type { KaavalSdkConfig } from "../src/config.js";
import { registerPasskey } from "../src/webauthn.js";

/**
 * jsdom does not implement the WebAuthn API (no real authenticator exists in
 * a CI/headless environment), so navigator.credentials is stubbed to return
 * a fake-but-well-formed PublicKeyCredential. This verifies the SDK's own
 * wiring (begin -> create() call shape -> finish) against the mock server,
 * which is the part T-AJ.2 owns; the actual authenticator ceremony can only
 * be verified in a real browser.
 */
function stubAuthenticatorCreate(): void {
  const create = vi.fn(async (options: CredentialCreationOptions) => {
    const publicKey = options.publicKey;
    if (!publicKey) throw new Error("expected publicKey options");

    // A real authenticator echoes the challenge back inside clientDataJSON.
    const challengeB64Url = base64UrlEncode(publicKey.challenge as ArrayBuffer);
    const clientData = JSON.stringify({
      type: "webauthn.create",
      challenge: challengeB64Url,
      origin: "https://kaaval-demo.local",
    });

    return {
      id: "fake-credential-id",
      rawId: base64UrlDecode("fake-credential-id").buffer,
      type: "public-key",
      response: {
        clientDataJSON: new TextEncoder().encode(clientData).buffer,
        attestationObject: new Uint8Array([1, 2, 3, 4]).buffer,
      },
    };
  });

  Object.defineProperty(globalThis.navigator, "credentials", {
    value: { create, get: vi.fn() },
    configurable: true,
  });
}

describe("registerPasskey", () => {
  let mockServer: ReturnType<typeof createMockServer>;
  let gatewayOrigin: string;

  beforeAll(async () => {
    mockServer = createMockServer();
    gatewayOrigin = await mockServer.listen();
    stubAuthenticatorCreate();
  });

  afterAll(async () => {
    await mockServer.close();
  });

  it("completes the ceremony and submits the session public key to the mock server", async () => {
    const config: KaavalSdkConfig = {
      relyingPartyId: "kaaval-demo.local",
      gatewayOrigin,
    };

    const result = await registerPasskey(config);

    expect(result.credentialId).toBe("fake-credential-id");
    expect(result.keyPair.publicKeyJwk.kty).toBe("EC");

    const state: MockServerState = mockServer.state;
    expect(state.lastRegisterPublicKeyJwk).toEqual(result.keyPair.publicKeyJwk);
    expect(state.lastAttestationResponse).toBeTruthy();
    expect((state.lastAttestationResponse as { id: string }).id).toBe("fake-credential-id");
  });
});
