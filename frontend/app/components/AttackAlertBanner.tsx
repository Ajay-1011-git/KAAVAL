"use client";

// AttackAlertBanner — added for the two-laptop LAN demo (attacker on Laptop B,
// this dashboard on Laptop A). It does NOT change how any decision is made: it
// only surfaces, prominently, the SecurityEvents the backend already emits when
// an attacker-driven request is blocked (or, in baseline mode, slips through).
// It reads the same SSE stream every other panel reads.
//
// OWNERSHIP NOTE (flagged for Sai / dashboard-chronicle): this component and
// its two-line mount in app/page.tsx are the only additions the demo makes to
// frontend/. Revert both to remove the callout; nothing else depends on it.

import { useEffect, useState } from "react";

import type { SecurityEvent } from "@/lib/contracts";
import { useSecurityEvents } from "@/lib/eventsClient";

const DISMISS_MS = 12_000;

type Alert = {
  kind: "blocked" | "exposed";
  title: string;
  reason: string;
  eventId: string;
};

// A legitimate first-party client never produces these — they are the fingerprint
// of an attacker replaying or tampering with a captured session.
const BLOCK_EVENT_TYPES = new Set<SecurityEvent["event_type"]>([
  "proof_absent",
  "signature_invalid",
  "request_blocked",
  "replay_attempted",
  "oauth_grant_blocked",
  "device_code_blocked",
]);

function classify(event: SecurityEvent): Alert | null {
  if (event.reason === "baseline_mode_no_proof_required") {
    return {
      kind: "exposed",
      title: "Attack succeeded — PulseLock is OFF (baseline)",
      reason: "A stolen session cookie alone was accepted. This is the vulnerability, shown live.",
      eventId: event.event_id,
    };
  }
  if (event.severity === "blocked" || BLOCK_EVENT_TYPES.has(event.event_type)) {
    return {
      kind: "blocked",
      title: "Attack in progress — blocked by PulseLock",
      reason: `${event.event_type.replaceAll("_", " ")} · ${event.reason.replaceAll("_", " ")}`,
      eventId: event.event_id,
    };
  }
  return null;
}

export function AttackAlertBanner() {
  const { events } = useSecurityEvents();
  const [dismissedId, setDismissedId] = useState<string | null>(null);

  // Derive the current alert during render from the latest event rather than
  // mirroring it into state from inside an effect. The only thing we keep in
  // state is which event has been dismissed — so a given attack is shown once,
  // and a newer one (always a distinct event_id) shows again. Same behaviour
  // as before, without a synchronous setState in an effect body.
  const latest = events.length > 0 ? events[events.length - 1] : null;
  const candidate = latest ? classify(latest) : null;
  const alert = candidate && candidate.eventId !== dismissedId ? candidate : null;

  // The auto-dismiss timer is the one genuine external system here. Its
  // setState runs in the timeout callback, not synchronously in the effect
  // body, so it does not cause the cascading renders the lint rule guards
  // against. Re-armed whenever a new alert becomes active.
  const activeId = alert?.eventId ?? null;
  useEffect(() => {
    if (!activeId) return;
    const handle = setTimeout(() => setDismissedId(activeId), DISMISS_MS);
    return () => clearTimeout(handle);
  }, [activeId]);

  if (!alert) return null;

  const blocked = alert.kind === "blocked";
  const palette = blocked
    ? "border-rose-400/50 bg-rose-500/15 text-rose-100"
    : "border-amber-400/50 bg-amber-500/15 text-amber-100";
  const dot = blocked ? "bg-rose-400" : "bg-amber-400";

  return (
    <div
      role="alert"
      className={`mb-5 flex items-start gap-3 rounded-xl border px-4 py-3 shadow-lg shadow-black/20 ${palette}`}
    >
      <span
        aria-hidden="true"
        className={`mt-1 size-2.5 shrink-0 animate-pulse rounded-full ${dot}`}
      />
      <div className="flex flex-col gap-0.5">
        <p className="text-sm font-semibold">{alert.title}</p>
        <p className="text-xs leading-5 opacity-90">{alert.reason}</p>
      </div>
      <button
        type="button"
        onClick={() => setDismissedId(alert.eventId)}
        className="ml-auto rounded-md px-2 py-1 text-xs opacity-70 hover:opacity-100"
        aria-label="Dismiss alert"
      >
        Dismiss
      </button>
    </div>
  );
}
