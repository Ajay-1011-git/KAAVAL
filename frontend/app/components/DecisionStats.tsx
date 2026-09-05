"use client";

// A counter band above the panels. Every number here is derived from the same
// SSE stream the panels read, never from a fixture or a prop, so it cannot
// show a decision that did not happen. It is also the one part of the page
// that genuinely moves: the counts change as the gateway emits, and the "last
// decision" clock ticks, which is what tells an operator at a glance whether
// the stream is alive or quietly dead.

import { useEffect, useMemo, useState } from "react";

import { useSecurityEvents } from "@/lib/eventsClient";

function relativeTime(fromMs: number, toMs: number) {
  const seconds = Math.max(0, Math.floor((toMs - fromMs) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function Stat({
  label,
  value,
  accent,
  size = "lg",
}: {
  label: string;
  value: string;
  accent?: boolean;
  size?: "lg" | "sm";
}) {
  return (
    <div className="bg-canvas px-5 py-6">
      <p className="text-meta font-mono text-[0.65rem] font-semibold tracking-[0.16em] uppercase">
        {label}
      </p>
      <p
        className={`tnum mt-3 leading-none font-bold ${
          size === "lg" ? "text-[2.5rem]" : "text-[1.5rem]"
        } ${accent ? "text-mint" : "text-hazard"}`}
      >
        {value}
      </p>
    </div>
  );
}

export function DecisionStats() {
  const { events } = useSecurityEvents();

  // Held at null until the first tick so the server and the first client
  // render agree: Date.now() differs between them and would otherwise be a
  // hydration mismatch.
  const [nowMs, setNowMs] = useState<number | null>(null);
  useEffect(() => {
    const handle = setInterval(() => setNowMs(Date.now()), 1000);
    return () => clearInterval(handle);
  }, []);

  const counts = useMemo(() => {
    let blocked = 0;
    let warning = 0;
    for (const event of events) {
      if (event.severity === "blocked") blocked += 1;
      else if (event.severity === "warning") warning += 1;
    }
    return { blocked, warning };
  }, [events]);

  const latest = events.at(-1);
  const lastSeen =
    latest && nowMs !== null
      ? relativeTime(Date.parse(latest.timestamp), nowMs)
      : latest
        ? "just now"
        : "none yet";

  return (
    // gap-px over a tinted background draws the hairlines. The design spec uses
    // 1px rules where another system would reach for a card and a shadow.
    <section
      aria-label="Decision counters"
      className="border-hazard/15 bg-hazard/15 mt-8 grid grid-cols-2 gap-px overflow-hidden rounded-tile border sm:grid-cols-4"
    >
      <Stat label="Blocked" value={String(counts.blocked)} accent />
      <Stat label="Warnings" value={String(counts.warning)} />
      <Stat label="Decisions seen" value={String(events.length)} />
      <Stat label="Last decision" value={lastSeen} size="sm" />
    </section>
  );
}
