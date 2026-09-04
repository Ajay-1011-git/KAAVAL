"use client";

import type { SecurityEvent } from "@/lib/contracts";
import {
  type EventStreamStatus,
  useSecurityEvents,
} from "@/lib/eventsClient";

const severityStyles: Record<SecurityEvent["severity"], string> = {
  info: "border-sky-300/20 bg-sky-300/10 text-sky-200",
  warning: "border-amber-300/20 bg-amber-300/10 text-amber-200",
  blocked: "border-rose-300/25 bg-rose-300/10 text-rose-200",
};

const statusLabels: Record<EventStreamStatus, string> = {
  connecting: "Connecting",
  open: "Live",
  reconnecting: "Reconnecting",
};

function formatEventType(value: SecurityEvent["event_type"]) {
  return value.replaceAll("_", " ");
}

function formatTimestamp(value: string) {
  return new Intl.DateTimeFormat("en", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
    timeZone: "UTC",
  }).format(new Date(value));
}

export function LiveEventFeed() {
  const { events, status, warning } = useSecurityEvents();

  return (
    <section
      aria-labelledby="live-event-feed-title"
      className="flex min-h-72 flex-col rounded-2xl border border-white/10 bg-slate-900/70 p-5 shadow-2xl shadow-black/10 sm:p-6 lg:col-span-8"
    >
      <div className="flex items-start justify-between gap-4 border-b border-white/10 pb-4">
        <div>
          <p className="text-[0.68rem] font-semibold tracking-[0.2em] text-emerald-300 uppercase">
            Decision stream
          </p>
          <h2
            id="live-event-feed-title"
            className="mt-2 text-xl font-semibold tracking-tight text-white"
          >
            Live event feed
          </h2>
        </div>
        <div className="flex items-center gap-2 rounded-full border border-white/10 bg-white/5 px-3 py-1.5 text-[0.65rem] font-semibold tracking-wide text-slate-300 uppercase">
          <span
            aria-hidden="true"
            className={`size-2 rounded-full ${
              status === "open"
                ? "bg-emerald-300 shadow-[0_0_10px_rgba(110,231,183,0.75)]"
                : "animate-pulse bg-amber-300"
            }`}
          />
          {statusLabels[status]}
        </div>
      </div>

      <div aria-live="polite" className="flex-1 pt-4">
        {warning ? (
          <p className="mb-3 rounded-lg border border-amber-300/15 bg-amber-300/5 px-3 py-2 text-xs text-amber-100">
            {warning}
          </p>
        ) : null}

        {events.length === 0 ? (
          <div className="grid min-h-48 place-items-center text-center">
            <div className="max-w-xs">
              <span
                aria-hidden="true"
                className="mx-auto mb-4 block size-10 rounded-full border border-dashed border-slate-600 bg-slate-950/50"
              />
              <p className="text-sm font-medium text-slate-300">
                Waiting for security events
              </p>
              <p className="mt-2 text-xs leading-5 text-slate-500">
                Decisions will appear here as the gateway and Guardian emit
                them.
              </p>
            </div>
          </div>
        ) : (
          <ol className="space-y-2">
            {events.map((event) => (
              <li
                key={event.event_id}
                className={`grid gap-3 rounded-xl border p-4 sm:grid-cols-[7rem_minmax(0,1fr)_auto] sm:items-center ${
                  event.severity === "blocked"
                    ? "border-rose-300/20 bg-rose-300/[0.055]"
                    : "border-white/10 bg-white/[0.025]"
                }`}
              >
                <div>
                  <time
                    dateTime={event.timestamp}
                    className="font-mono text-xs text-slate-500"
                  >
                    {formatTimestamp(event.timestamp)} UTC
                  </time>
                </div>
                <div className="min-w-0">
                  <p className="truncate text-sm font-semibold text-white capitalize">
                    {formatEventType(event.event_type)}
                  </p>
                  <p className="mt-1 break-words font-mono text-xs text-slate-400">
                    {event.reason}
                  </p>
                </div>
                <span
                  className={`w-fit rounded-full border px-2 py-1 text-[0.65rem] font-semibold uppercase ${severityStyles[event.severity]}`}
                >
                  {event.severity}
                </span>
              </li>
            ))}
          </ol>
        )}
      </div>
    </section>
  );
}
