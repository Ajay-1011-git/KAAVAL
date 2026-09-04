// @vitest-environment jsdom
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createMockServer, type MockServerState } from "../mock-server/index.js";
import { base64UrlDecode, base64UrlEncode } from "../src/base64url.js";
import type { KaavalSdkConfig } from "../src/config.js";
import {
  clearActiveSession,
  getActiveSession,
  loginWithPasskey,
  registerPasskey,
} from "../src/webauthn.js";

/**
 * jsdom does not implement the WebAuthn API (no real authenticator exists in
 * a CI/headless environment), so navigator.credentials is stubbed to return
 * a fake-but-well-formed PublicKeyCredential. This verifies the SDK's own
 * wiring (begin -> create() call shape -> finish) against the mock server,
 * which is the part T-AJ.2 owns; the actual authenticator ceremony can only
 * be verified in a real browser.
 */
function stubAuthenticator(): void {
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

describe("webauthn ceremonies", () => {
  let mockServer: ReturnType<typeof createMockServer>;
  let gatewayOrigin: string;
  let config: KaavalSdkConfig;

  beforeAll(async () => {
    mockServer = createMockServer();
    gatewayOrigin = await mockServer.listen();
    config = { relyingPartyId: "kaaval-demo.local", gatewayOrigin };
    stubAuthenticator();
  });

  afterAll(async () => {
    await mockServer.close();
  });

  it("registration completes and submits the session public key to the mock server", async () => {
    const result = await registerPasskey(config, "demo@kaaval.local");

    expect(result.credentialId).toBe("fake-credential-id");
    expect(result.keyPair.publicKeyJwk.kty).toBe("EC");

    const state: MockServerState = mockServer.state;
    expect(state.lastRegisterPublicKeyJwk).toEqual(result.keyPair.publicKeyJwk);
    expect(state.lastAttestationResponse).toBeTruthy();
    expect((state.lastAttestationResponse as { id: string }).id).toBe("fake-credential-id");
  });

  it("login binds a fresh session public key and returns a session_id", async () => {
    clearActiveSession();
    expect(getActiveSession()).toBeNull();

    const sessionId = await loginWithPasskey(config, "demo@kaaval.local");

    const state: MockServerState = mockServer.state;
    expect(sessionId).toBe(state.activeSessionId);
    expect(sessionId.length).toBeGreaterThan(0);

    // The server received the session public key it must bind the session to.
    expect(state.lastLoginPublicKeyJwk).toBeTruthy();
    expect(state.lastLoginPublicKeyJwk?.kty).toBe("EC");

    // ...and it is the same key the SDK stored for signing later requests.
    const session = getActiveSession();
    expect(session).not.toBeNull();
    expect(session?.sessionId).toBe(sessionId);
    expect(session?.keyPair.publicKeyJwk).toEqual(state.lastLoginPublicKeyJwk);
    expect(session?.keyPair.privateKey.extractable).toBe(false);
  });

  it("submits the full assertion response to login/finish", async () => {
    await loginWithPasskey(config, "demo@kaaval.local");

    const assertion = mockServer.state.lastAssertionResponse as {
      id: string;
      type: string;
      response: Record<string, string | null>;
    };
    expect(assertion.id).toBe("fake-credential-id");
    expect(assertion.type).toBe("public-key");
    expect(assertion.response.clientDataJSON).toBeTruthy();
    expect(assertion.response.authenticatorData).toBeTruthy();
    expect(assertion.response.signature).toBeTruthy();
    expect(assertion.response.userHandle).toBeNull();
  });

  it("binds a distinct session key pair per login", async () => {
    const firstSessionId = await loginWithPasskey(config, "demo@kaaval.local");
    const firstJwk = getActiveSession()?.keyPair.publicKeyJwk;

    const secondSessionId = await loginWithPasskey(config, "demo@kaaval.local");
    const secondJwk = getActiveSession()?.keyPair.publicKeyJwk;

    expect(secondSessionId).not.toBe(firstSessionId);
    expect(secondJwk).not.toEqual(firstJwk);
  });

  it("rejects a server RP ID that does not match the configured one", async () => {
    await expect(
      loginWithPasskey({ relyingPartyId: "evil-proxy.example", gatewayOrigin }, "demo@kaaval.local"),
    ).rejects.toThrow(/does not match configured relyingPartyId/);
  });
});
