// T-AJ.6 — protection-state indicator. Plain DOM, no framework dependency,
// no network calls of its own — it only reads session state exposed by
// client.ts (T-AJ.5, itself re-exporting webauthn.ts's single source of
// truth for the active session). This is the demo's visual "before/after"
// moment: unprotected vs. PulseLock-bound.
import { getActiveSession } from "./client.js";

const PROTECTED_STYLE =
  "position:fixed;bottom:12px;right:12px;z-index:2147483647;font:12px/1.4 system-ui,sans-serif;" +
  "padding:6px 10px;border-radius:6px;color:#fff;background:#166534;box-shadow:0 1px 4px rgba(0,0,0,0.3);";

const UNPROTECTED_STYLE =
  "position:fixed;bottom:12px;right:12px;z-index:2147483647;font:12px/1.4 system-ui,sans-serif;" +
  "padding:6px 10px;border-radius:6px;color:#fff;background:#7f1d1d;box-shadow:0 1px 4px rgba(0,0,0,0.3);";

/** A short, non-secret fingerprint derived from the bound public key's x-coordinate. */
function shortFingerprint(publicKeyJwk: JsonWebKey): string {
  return (publicKeyJwk.x ?? "").slice(0, 8) || "unknown";
}

export interface ProtectionIndicatorHandle {
  /** The mounted DOM element, in case the host app wants to reposition/restyle it. */
  element: HTMLElement;
  /** Re-checks session state and updates the rendered text/style. Call after login/logout. */
  refresh(): void;
  /** Removes the element from the DOM. */
  destroy(): void;
}

/**
 * Creates and mounts a small fixed-position indicator showing whether the
 * current session is PulseLock-protected. Does not poll or make network
 * calls — the host app calls refresh() after a login/logout state change.
 */
export function createProtectionIndicator(target: HTMLElement = document.body): ProtectionIndicatorHandle {
  const element = document.createElement("div");
  element.setAttribute("data-kaaval-indicator", "true");

  function refresh(): void {
    const session = getActiveSession();
    if (session) {
      element.setAttribute("style", PROTECTED_STYLE);
      element.textContent = `Protected · ${shortFingerprint(session.keyPair.publicKeyJwk)}`;
    } else {
      element.setAttribute("style", UNPROTECTED_STYLE);
      element.textContent = "Not protected";
    }
  }

  refresh();
  target.appendChild(element);

  return {
    element,
    refresh,
    destroy(): void {
      element.remove();
    },
  };
}
