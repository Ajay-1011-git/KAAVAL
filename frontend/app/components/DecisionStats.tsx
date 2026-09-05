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

// Four identical bordered boxes read as one undifferentiated strip, so the
// cells step down a tonal ramp from left to right, which is also their order
// of importance. Depth comes from the fill, never a shadow, as everywhere
// else here.
//
// `blocked` takes the mint fill deliberately: mint already means "PulseLock
// stopped this" on every BLOCKED tag in the decision stream below, so the
// headline count wears the same colour as the thing it counts.
const TONES = {
  blocked: {
    surface: "bg-mint",
    label: "text-inverted/70",
    value: "text-inverted",
  },
  raised: {
    surface: "bg-surface",
    label: "text-meta",
    value: "text-hazard",
  },
  riser: {
    surface: "bg-riser",
    label: "text-meta",
    value: "text-hazard",
  },
  flat: {
    surface: "bg-canvas",
    label: "text-meta",
    value: "text-hazard",
  },
} as const;

function Stat({
  label,
  value,
  tone,
  size = "lg",
}: {
  label: string;
  value: string;
  tone: keyof typeof TONES;
  size?: "lg" | "sm";
}) {
  const { surface, label: labelTone, value: valueTone } = TONES[tone];

  return (
    <div className={`${surface} px-5 py-6`}>
      <p
        className={`${labelTone} font-mono text-[0.65rem] font-semibold tracking-[0.16em] uppercase`}
      >
        {label}
      </p>
      <p
        className={`tnum ${valueTone} mt-3 leading-none font-bold ${
          size === "lg" ? "text-[2.5rem]" : "text-[1.5rem]"
        }`}
      >
        {value}
      </p>
    </div>
  );
}

export function DecisionStats() {
  const { events, status, synced } = useSecurityEvents();

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

  // Until the gateway has finished replaying its recorded history these
  // counts are a partial tally that climbs on screen, which reads as the
  // numbers being unstable rather than as a page still loading. Hold the
  // placeholder until the totals are settled, then let them tick up live.
  const settled = synced || status === "unconfigured";
  const show = (value: string) => (settled ? value : "--");

  return (
    // gap-px over a tinted background draws the hairlines. The design spec uses
    // 1px rules where another system would reach for a card and a shadow.
    <section
      aria-label="Decision counters"
      className="border-hazard/15 bg-hazard/15 mt-8 grid grid-cols-2 gap-px overflow-hidden rounded-tile border sm:grid-cols-4"
    >
      <Stat label="Blocked" value={show(String(counts.blocked))} tone="blocked" />
      <Stat label="Warnings" value={show(String(counts.warning))} tone="raised" />
      <Stat label="Recorded" value={show(String(events.length))} tone="riser" />
      <Stat
        label="Last decision"
        value={show(lastSeen)}
        tone="flat"
        size="sm"
      />
    </section>
  );
}
