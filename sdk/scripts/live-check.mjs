// Drives the REAL compiled SDK (sdk/dist) against the REAL gateway.
//
// This is the same code path frontend/app/demo/page.tsx imports. The only
// stub is the authenticator itself: navigator.credentials is replaced with a
// genuine ECDSA P-256 authenticator, exactly as a browser's would behave,
// because a headless Node process has no passkey hardware. Everything else —
// the ceremonies, the canonical string, the signature, the X-KAAVAL-Proof
// header, the sequence counter — is the shipped SDK.

import { webcrypto } from "node:crypto";
import {
  registerPasskey,
  loginWithPasskey,
  kaavalFetch,
  getActiveSession,
} from "../dist/index.js";

const GATEWAY = process.env.GATEWAY ?? "http://127.0.0.1:8500";
const PAGE_ORIGIN = process.env.PAGE_ORIGIN ?? "http://localhost:3000";
const RP_ID = process.env.RP_ID ?? "localhost";

// --- minimal CBOR encoder (only the shapes an authenticator emits) ---
const b = (...xs) => Buffer.concat(xs.map((x) => (Buffer.isBuffer(x) ? x : Buffer.from(x))));
const uint = (n) => (n < 24 ? Buffer.from([n]) : Buffer.from([0x18, n]));
const negInt = (n) => Buffer.from([0x20 | (-1 - n)]); // -1 -> 0x20, -7 -> 0x26
const bytes = (buf) =>
  buf.length < 24
    ? b(Buffer.from([0x40 | buf.length]), buf)
    : buf.length < 256
      ? b(Buffer.from([0x58, buf.length]), buf)
      : b(Buffer.from([0x59, buf.length >> 8, buf.length & 0xff]), buf);
const text = (s) => b(Buffer.from([0x60 | s.length]), Buffer.from(s, "utf8"));

function cosePublicKey(x, y) {
  return b(
    Buffer.from([0xa5]), // 5-entry map
    uint(1), uint(2),            // kty: EC2
    uint(3), negInt(-7),         // alg: ES256
    negInt(-1), uint(1),         // crv: P-256
    negInt(-2), bytes(x),        // x
    negInt(-3), bytes(y),        // y
  );
}

function attestationObject(authData) {
  return b(
    Buffer.from([0xa3]),
    text("fmt"), text("none"),
    text("attStmt"), Buffer.from([0xa0]),
    text("authData"), bytes(authData),
  );
}

const b64url = (buf) => Buffer.from(buf).toString("base64url");
const sha256 = (buf) =>
  Buffer.from(new Uint8Array(webcrypto.subtle.digestSync?.("SHA-256", buf) ?? []));

async function digest(data) {
  return Buffer.from(await webcrypto.subtle.digest("SHA-256", data));
}

// --- a real P-256 authenticator ---
const passkey = await webcrypto.subtle.generateKey(
  { name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"],
);
const jwk = await webcrypto.subtle.exportKey("jwk", passkey.publicKey);
const credentialId = webcrypto.getRandomValues(new Uint8Array(16));
let signCount = 0;

async function authenticatorData(includeCredential) {
  const rpIdHash = await digest(Buffer.from(RP_ID, "utf8"));
  const flags = Buffer.from([includeCredential ? 0x45 : 0x05]); // UP|UV(|AT)
  const counter = Buffer.alloc(4);
  counter.writeUInt32BE(++signCount);
  if (!includeCredential) return b(rpIdHash, flags, counter);
  const aaguid = Buffer.alloc(16);
  const idLen = Buffer.alloc(2);
  idLen.writeUInt16BE(credentialId.length);
  const cose = cosePublicKey(
    Buffer.from(jwk.x, "base64url"),
    Buffer.from(jwk.y, "base64url"),
  );
  return b(rpIdHash, flags, counter, aaguid, idLen, Buffer.from(credentialId), cose);
}

function clientData(type, challenge) {
  return Buffer.from(JSON.stringify({
    type, challenge: b64url(challenge), origin: PAGE_ORIGIN, crossOrigin: false,
  }), "utf8");
}

const toArrayBuffer = (buf) =>
  buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);

Object.defineProperty(globalThis, "navigator", { configurable: true, writable: true, value: {
  credentials: {
    async create({ publicKey }) {
      const cd = clientData("webauthn.create", Buffer.from(publicKey.challenge));
      const authData = await authenticatorData(true);
      return {
        id: b64url(credentialId),
        rawId: toArrayBuffer(Buffer.from(credentialId)),
        type: "public-key",
        response: {
          clientDataJSON: toArrayBuffer(cd),
          attestationObject: toArrayBuffer(attestationObject(authData)),
        },
      };
    },
    async get({ publicKey }) {
      const cd = clientData("webauthn.get", Buffer.from(publicKey.challenge));
      const authData = await authenticatorData(false);
      const signed = b(authData, await digest(cd));
      const raw = await webcrypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" }, passkey.privateKey, signed,
      );
      // Web Crypto emits raw r||s; convert to DER, which is what py_webauthn verifies.
      const sig = Buffer.from(raw);
      const der = (() => {
        const trim = (x) => { let i = 0; while (i < x.length - 1 && x[i] === 0) i++;
          const s = x.subarray(i); return s[0] & 0x80 ? b(Buffer.from([0]), s) : s; };
        const r = trim(sig.subarray(0, 32)), s = trim(sig.subarray(32));
        const seq = b(Buffer.from([0x02, r.length]), r, Buffer.from([0x02, s.length]), s);
        return b(Buffer.from([0x30, seq.length]), seq);
      })();
      return {
        id: b64url(credentialId),
        rawId: toArrayBuffer(Buffer.from(credentialId)),
        type: "public-key",
        response: {
          clientDataJSON: toArrayBuffer(cd),
          authenticatorData: toArrayBuffer(authData),
          signature: toArrayBuffer(der),
          userHandle: null,
        },
      };
    },
  },
} });
Object.defineProperty(globalThis, "location", { configurable: true, writable: true, value: { origin: PAGE_ORIGIN } });

// A browser always attaches Origin to a cross-origin request and forbids
// scripts from setting it; Node does neither. Wrap fetch so the gateway sees
// what a real browser would send.
const realFetch = globalThis.fetch;
globalThis.fetch = (input, init = {}) => {
  const headers = new Headers(init.headers);
  if (!headers.has("Origin")) headers.set("Origin", PAGE_ORIGIN);
  return realFetch(input, { ...init, headers });
};

// --- run the SDK exactly as the demo page does ---
const config = { relyingPartyId: RP_ID, gatewayOrigin: GATEWAY };
const username = `browser-${Date.now()}@kaaval.local`;

console.log("=== FIX-1: the real SDK against the real gateway ===\n");

const reg = await registerPasskey(config, username);
console.log(`1. registerPasskey()  -> credential ${reg.credentialId.slice(0, 20)}…`);

const sessionId = await loginWithPasskey(config, username);
console.log(`2. loginWithPasskey() -> session ${sessionId.slice(0, 16)}…`);
console.log(`   indicator would read: ${getActiveSession() ? "Protected" : "Not protected"}`);

const res = await kaavalFetch(config, "/api/transfer?mode=protected", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ to_account: "acct-demo-1", amount: 250 }),
});
const body = await res.json();
console.log(`3. kaavalFetch()      -> HTTP ${res.status} ${JSON.stringify(body)}`);

const unsigned = await fetch(`${GATEWAY}/api/transfer?mode=protected`, {
  method: "POST",
  headers: { "Content-Type": "application/json", Origin: PAGE_ORIGIN },
  body: JSON.stringify({ to_account: "acct-demo-1", amount: 250 }),
});
const unsignedBody = await unsigned.json();
console.log(`4. same request, no proof -> HTTP ${unsigned.status} ${JSON.stringify(unsignedBody)}`);

const ok = res.status === 200 && unsigned.status === 401;
console.log(`\n=== ${ok ? "PASS" : "FAIL"}: signed accepted, unsigned blocked ===`);
process.exit(ok ? 0 : 1);
