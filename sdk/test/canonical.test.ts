import { describe, expect, it } from "vitest";
import { buildCanonicalString, buildEnvelope, type EnvelopeInput } from "../src/canonical.js";
import { generateSessionKeyPair } from "../src/keys.js";

const baseFields = {
  session_id: "sess-123",
  method: "POST",
  origin: "https://kaaval-demo.local",
  path: "/api/transfer",
  body_hash: "deadbeef",
  nonce: "nonce-abc",
  sequence: 1,
  timestamp: "2026-09-04T18:40:00.000Z",
};

describe("buildCanonicalString", () => {
  it("joins fields with newlines in the exact fixed order", () => {
    const result = buildCanonicalString(baseFields);
    expect(result).toBe(
      [
        "sess-123",
        "POST",
        "https://kaaval-demo.local",
        "/api/transfer",
        "deadbeef",
        "nonce-abc",
        "1",
        "2026-09-04T18:40:00.000Z",
      ].join("\n"),
    );
  });
});

describe("buildEnvelope", () => {
  const baseInput: EnvelopeInput = {
    session_id: "sess-123",
    method: "POST",
    origin: "https://kaaval-demo.local",
    path: "/api/transfer",
    body: JSON.stringify({ amount: 100 }),
    nonce: "nonce-abc",
    sequence: 1,
  };

  it("produces a well-formed envelope with a hex body_hash and ISO-8601 UTC timestamp", async () => {
    const keyPair = await generateSessionKeyPair();
    const envelope = await buildEnvelope(baseInput, keyPair.sign);

    expect(envelope.session_id).toBe(baseInput.session_id);
    expect(envelope.method).toBe(baseInput.method);
    expect(envelope.origin).toBe(baseInput.origin);
    expect(envelope.path).toBe(baseInput.path);
    expect(envelope.nonce).toBe(baseInput.nonce);
    expect(envelope.sequence).toBe(baseInput.sequence);
    expect(envelope.body_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(envelope.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    expect(typeof envelope.signature).toBe("string");
    expect(envelope.signature.length).toBeGreaterThan(0);
  });

  it("computes body_hash as the real SHA-256 of the exact raw body bytes", async () => {
    const keyPair = await generateSessionKeyPair();
    const envelope = await buildEnvelope(baseInput, keyPair.sign);

    const rawBody = baseInput.body;
    if (typeof rawBody !== "string") throw new Error("expected string body in this test fixture");
    const expectedDigest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rawBody));
    const expectedHex = Array.from(new Uint8Array(expectedDigest))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    expect(envelope.body_hash).toBe(expectedHex);
  });

  it("changes the signature when the path changes and nothing else", async () => {
    const keyPair = await generateSessionKeyPair();
    const envelopeA = await buildEnvelope(baseInput, keyPair.sign);
    const envelopeB = await buildEnvelope({ ...baseInput, path: "/api/other" }, keyPair.sign);

    expect(envelopeB.signature).not.toBe(envelopeA.signature);
  });

  it("changes the signature when the body changes (and therefore body_hash changes)", async () => {
    const keyPair = await generateSessionKeyPair();
    const envelopeA = await buildEnvelope(baseInput, keyPair.sign);
    const envelopeB = await buildEnvelope(
      { ...baseInput, body: JSON.stringify({ amount: 999 }) },
      keyPair.sign,
    );

    expect(envelopeB.body_hash).not.toBe(envelopeA.body_hash);
    expect(envelopeB.signature).not.toBe(envelopeA.signature);
  });

  it("changes the signature when session_id, nonce, or sequence changes", async () => {
    const keyPair = await generateSessionKeyPair();
    const base = await buildEnvelope(baseInput, keyPair.sign);

    const withDifferentSession = await buildEnvelope(
      { ...baseInput, session_id: "sess-999" },
      keyPair.sign,
    );
    const withDifferentNonce = await buildEnvelope({ ...baseInput, nonce: "nonce-xyz" }, keyPair.sign);
    const withDifferentSequence = await buildEnvelope({ ...baseInput, sequence: 2 }, keyPair.sign);

    expect(withDifferentSession.signature).not.toBe(base.signature);
    expect(withDifferentNonce.signature).not.toBe(base.signature);
    expect(withDifferentSequence.signature).not.toBe(base.signature);
  });

  it("produces a signature verifiable against the public key", async () => {
    const keyPair = await generateSessionKeyPair();
    const envelope = await buildEnvelope(baseInput, keyPair.sign);

    const canonicalString = buildCanonicalString({
      session_id: envelope.session_id,
      method: envelope.method,
      origin: envelope.origin,
      path: envelope.path,
      body_hash: envelope.body_hash,
      nonce: envelope.nonce,
      sequence: envelope.sequence,
      timestamp: envelope.timestamp,
    });

    const publicKey = await crypto.subtle.importKey(
      "jwk",
      keyPair.publicKeyJwk,
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["verify"],
    );
    const signatureBytes = Uint8Array.from(atob(envelope.signature), (c) => c.charCodeAt(0));
    const valid = await crypto.subtle.verify(
      { name: "ECDSA", hash: { name: "SHA-256" } },
      publicKey,
      signatureBytes,
      new TextEncoder().encode(canonicalString),
    );

    expect(valid).toBe(true);
  });
});
