import { describe, expect, it } from "vitest";
import { generateSessionKeyPair } from "../src/keys.js";

describe("generateSessionKeyPair", () => {
  it("generates a key pair with an exportable public key", async () => {
    const keyPair = await generateSessionKeyPair();
    expect(keyPair.publicKeyJwk).toBeDefined();
    expect(keyPair.publicKeyJwk.kty).toBe("EC");
    expect(keyPair.publicKeyJwk.crv).toBe("P-256");
  });

  it("generates a non-exportable private key", async () => {
    const keyPair = await generateSessionKeyPair();
    expect(keyPair.privateKey.extractable).toBe(false);
    await expect(
      crypto.subtle.exportKey("jwk", keyPair.privateKey),
    ).rejects.toThrow();
  });

  it("signs data with the private key and produces a verifiable signature", async () => {
    const keyPair = await generateSessionKeyPair();
    const data = new TextEncoder().encode("hello kaaval");
    const signatureB64 = await keyPair.sign(data);
    expect(typeof signatureB64).toBe("string");
    expect(signatureB64.length).toBeGreaterThan(0);

    const publicKey = await crypto.subtle.importKey(
      "jwk",
      keyPair.publicKeyJwk,
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["verify"],
    );
    const signatureBytes = Uint8Array.from(atob(signatureB64), (c) =>
      c.charCodeAt(0),
    );
    const valid = await crypto.subtle.verify(
      { name: "ECDSA", hash: { name: "SHA-256" } },
      publicKey,
      signatureBytes,
      data,
    );
    expect(valid).toBe(true);
  });
});
