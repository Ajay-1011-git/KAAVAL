// sdk/src/index.ts — the package's public API (amendment FIX-2).
//
// package.json has always pointed "main" here, but the file did not exist, so
// `import { loginWithPasskey } from "@kaaval/sdk"` threw and nothing outside
// the SDK's own tests could consume it. This is that entry point.
//
// Only the surface a host application needs is re-exported. The internals
// (base64url helpers, envelope builders, the sequence-counter reset used by
// tests) stay unexported so the public API is the thing that has to stay
// stable, not the implementation.

// --- Configuration ---------------------------------------------------
export type { KaavalSdkConfig } from "./config.js";

// --- Session keys (T-AJ.1) -------------------------------------------
export { generateSessionKeyPair, type SessionKeyPair } from "./keys.js";

// --- WebAuthn ceremonies (T-AJ.2, T-AJ.3) ----------------------------
export {
  registerPasskey,
  loginWithPasskey,
  getActiveSession,
  clearActiveSession,
  type RegistrationResult,
  type ActiveSession,
} from "./webauthn.js";

// --- Signed requests (T-AJ.4, T-AJ.5, T-AJ.7) ------------------------
export {
  kaavalFetch,
  KaavalNoActiveSessionError,
  type KaavalFetchOptions,
} from "./client.js";

// The envelope type is part of the wire contract with the gateway
// (TRD §6.1), so a host app that inspects a proof header needs it.
export type { SignedRequestEnvelope } from "./canonical.js";

// --- Protection-state indicator (T-AJ.6) -----------------------------
export {
  createProtectionIndicator,
  type ProtectionIndicatorHandle,
} from "./indicator.js";
