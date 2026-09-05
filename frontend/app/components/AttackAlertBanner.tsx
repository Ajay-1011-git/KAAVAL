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
      title: "Attack succeeded. PulseLock is off (baseline)",
      reason: "A stolen session cookie alone was accepted. This is the vulnerability, shown live.",
      eventId: event.event_id,
    };
  }
  if (event.severity === "blocked" || BLOCK_EVENT_TYPES.has(event.event_type)) {
    return {
      kind: "blocked",
      title: "Attack in progress. Blocked by PulseLock",
      reason: `${event.event_type.replaceAll("_", " ")} / ${event.reason.replaceAll("_", " ")}`,
      eventId: event.event_id,
    };
  }
  return null;
}

export function AttackAlertBanner() {
  const { events, synced, liveFromIndex } = useSecurityEvents();
  const [dismissedId, setDismissedId] = useState<string | null>(null);

  // Derive the current alert during render from the latest event rather than
  // mirroring it into state from inside an effect. The only thing we keep in
  // state is which event has been dismissed — so a given attack is shown once,
  // and a newer one (always a distinct event_id) shows again.
  //
  // Only events that arrived AFTER the gateway finished replaying its history
  // are candidates. This banner claims an attack is happening now; on a page
  // reload the gateway replays every recorded event, and each one is briefly
  // the newest, so without this guard the banner flashed through the whole
  // back catalogue announcing attacks that ended hours ago.
  const hasLiveEvent = synced && events.length > liveFromIndex;
  const latest = hasLiveEvent ? events[events.length - 1] : null;
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
  // Colour as elevation, per the design spec: a saturated fill rather than a
  // shadow. The kind is also stated in the title text, so the meaning does not
  // rest on colour alone.
  const fill = blocked
    ? "bg-mint text-inverted"
    : "bg-ultraviolet text-hazard";

  return (
    <div
      role="alert"
      className={`rounded-feature mt-8 flex flex-wrap items-start gap-4 p-6 ${fill}`}
    >
      <span
        aria-hidden="true"
        className={`mt-1.5 size-2.5 shrink-0 animate-pulse rounded-full ${
          blocked ? "bg-inverted" : "bg-hazard"
        }`}
      />
      <div className="min-w-0 flex-1">
        <p className="font-mono text-[0.8rem] font-semibold tracking-[0.16em] uppercase">
          {alert.title}
        </p>
        <p className="mt-2 text-sm leading-5 opacity-90">{alert.reason}</p>
      </div>
      <button
        type="button"
        onClick={() => setDismissedId(alert.eventId)}
        className="rounded-cta min-h-11 cursor-pointer border border-current px-4 font-mono text-[0.65rem] font-semibold tracking-[0.14em] uppercase transition-opacity duration-150 hover:opacity-70"
      >
        Dismiss
      </button>
    </div>
  );
}
