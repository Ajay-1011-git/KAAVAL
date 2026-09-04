// B.1 — SDK init config. Passed in by the integrating app, never read from
// env vars (this is a browser package).
export interface KaavalSdkConfig {
  /** Must match the server's WebAuthn RP ID exactly, e.g. "kaaval-demo.local". */
  relyingPartyId: string;
  /** The gateway's real origin, e.g. "https://kaaval-demo.local". */
  gatewayOrigin: string;
}
