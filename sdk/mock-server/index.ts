// Local mock server implementing the *purpose* of the endpoints listed in
// TRD §5 / build-doc §B.2, with placeholder challenge/response data — not a
// real WebAuthn library server. Used only to verify the SDK's request wiring
// standalone, per this build document's instructions.
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { randomUUID, randomBytes } from "node:crypto";

function base64UrlEncodeBytes(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export interface DecodedProofEnvelope {
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

export interface MockServerState {
  lastRegisterPublicKeyJwk: JsonWebKey | null;
  lastLoginPublicKeyJwk: JsonWebKey | null;
  lastAttestationResponse: unknown;
  lastAssertionResponse: unknown;
  issuedNonces: Set<string>;
  registeredCredentialId: string | null;
  activeSessionId: string | null;
  /** Every X-KAAVAL-Proof envelope this mock server has decoded, in arrival order. */
  receivedProofEnvelopes: DecodedProofEnvelope[];
  /** The username each ceremony submitted — the gateway requires one. */
  lastRegisterUsername: string | null;
  lastLoginUsername: string | null;
  /** The raw URL of the most recent /api/ request, query string included. */
  lastRequestUrl: string | null;
}

function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk) => (data += chunk));
    req.on("end", () => {
      if (!data) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(data));
      } catch (err) {
        reject(err);
      }
    });
    req.on("error", reject);
  });
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(payload);
}

export function createMockServer() {
  const state: MockServerState = {
    lastRegisterPublicKeyJwk: null,
    lastLoginPublicKeyJwk: null,
    lastAttestationResponse: null,
    lastAssertionResponse: null,
    issuedNonces: new Set(),
    registeredCredentialId: null,
    activeSessionId: null,
    receivedProofEnvelopes: [],
    lastRegisterUsername: null,
    lastLoginUsername: null,
    lastRequestUrl: null,
  };

  const server = createServer((req, res) => {
    void (async () => {
      try {
        const url = req.url ?? "";

        if (req.method === "POST" && url === "/auth/webauthn/register/begin") {
          sendJson(res, 200, {
            challenge: base64UrlEncodeBytes(randomBytes(32)),
            rp: { id: "kaaval-demo.local", name: "KAAVAL Demo" },
            user: {
              id: base64UrlEncodeBytes(randomBytes(16)),
              name: "demo-user",
              displayName: "Demo User",
            },
            pubKeyCredParams: [{ type: "public-key", alg: -7 }],
            timeout: 60000,
            attestation: "none",
          });
          return;
        }

        if (req.method === "POST" && url === "/auth/webauthn/register/finish") {
          const body = await readJsonBody(req);
          // Field names mirror the real gateway (backend/gateway/webauthn_routes.py)
          // so this mock cannot drift into passing for a shape the server rejects.
          state.lastRegisterPublicKeyJwk = (body.session_public_key as JsonWebKey | undefined) ?? null;
          state.lastAttestationResponse = body.credential ?? null;
          const attestationId =
            typeof body.credential === "object" && body.credential !== null
              ? (body.credential as { id?: unknown }).id
              : undefined;
          state.registeredCredentialId = typeof attestationId === "string" ? attestationId : randomUUID();
          state.lastRegisterUsername = typeof body.username === "string" ? body.username : null;
          sendJson(res, 200, { verified: true, credential_id: state.registeredCredentialId, user_id: "user-mock-1" });
          return;
        }

        if (req.method === "POST" && url === "/auth/webauthn/login/begin") {
          sendJson(res, 200, {
            challenge: base64UrlEncodeBytes(randomBytes(32)),
            rpId: "kaaval-demo.local",
            allowCredentials: state.registeredCredentialId
              ? [{ id: state.registeredCredentialId, type: "public-key" }]
              : [],
            userVerification: "preferred",
            timeout: 60000,
          });
          return;
        }

        if (req.method === "POST" && url === "/auth/webauthn/login/finish") {
          const body = await readJsonBody(req);
          state.lastLoginPublicKeyJwk = (body.session_public_key as JsonWebKey | undefined) ?? null;
          state.lastAssertionResponse = body.credential ?? null;
          state.lastLoginUsername = typeof body.username === "string" ? body.username : null;
          state.activeSessionId = randomUUID();
          sendJson(res, 200, { session_id: state.activeSessionId });
          return;
        }

        if (req.method === "POST" && url === "/auth/nonce") {
          const nonce = randomUUID();
          state.issuedNonces.add(nonce);
          sendJson(res, 200, { nonce, issued_at: new Date().toISOString() });
          return;
        }

        if (url.startsWith("/api/")) {
          // Recorded so a test can assert the query string survived on the
          // wire even though it is deliberately outside the signature.
          state.lastRequestUrl = url;
          const proofHeader = req.headers["x-kaaval-proof"];
          if (typeof proofHeader === "string") {
            const decoded = JSON.parse(
              Buffer.from(proofHeader, "base64").toString("utf8"),
            ) as DecodedProofEnvelope;
            state.receivedProofEnvelopes.push(decoded);
          }
          sendJson(res, 200, { received: true, path: url, method: req.method, hadProof: typeof proofHeader === "string" });
          return;
        }

        sendJson(res, 404, { error: "not_found" });
      } catch (err) {
        sendJson(res, 500, { error: (err as Error).message });
      }
    })();
  });

  return {
    state,
    listen(): Promise<string> {
      return new Promise((resolve) => {
        server.listen(0, "127.0.0.1", () => {
          const address = server.address();
          if (address && typeof address === "object") {
            resolve(`http://127.0.0.1:${address.port}`);
          }
        });
      });
    },
    close(): Promise<void> {
      return new Promise((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
    },
  };
}
