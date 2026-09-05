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

import { useEffect, useRef, useState } from "react";

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
  const [alert, setAlert] = useState<Alert | null>(null);
  const lastSeenId = useRef<string | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (events.length === 0) return;
    const latest = events[events.length - 1];
    if (latest.event_id === lastSeenId.current) return;
    lastSeenId.current = latest.event_id;

    const next = classify(latest);
    if (!next) return;

    setAlert(next);
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => setAlert(null), DISMISS_MS);

    return () => {
      if (timer.current) clearTimeout(timer.current);
    };
  }, [events]);

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
        onClick={() => setAlert(null)}
        className="ml-auto rounded-md px-2 py-1 text-xs opacity-70 hover:opacity-100"
        aria-label="Dismiss alert"
      >
        Dismiss
      </button>
    </div>
  );
}
