"use client";

import { Panel, Tag } from "@/app/components/vergeUi";
import type { SecurityEvent } from "@/lib/contracts";
import { IST_TIME_ZONE } from "@/lib/displayTime";
import { type EventStreamStatus, useSecurityEvents } from "@/lib/eventsClient";

// The stream buffers up to 100 events and this panel used to render every one
// of them, so a few minutes of demo traffic buried the decision that actually
// mattered under a wall of identical rows. Only the newest few are shown, and
// the count below the list states plainly how many are being held back.
const MAX_VISIBLE = 6;

const statusLabels: Record<EventStreamStatus, string> = {
  unconfigured: "No backend",
  connecting: "Connecting",
  open: "Live",
  reconnecting: "Reconnecting",
};

// Severity is carried by a labelled pill, not by colour alone, so the feed
// stays readable for colour-blind viewers and in a washed-out projector image.
function severityTone(severity: SecurityEvent["severity"]) {
  if (severity === "blocked") return "mint" as const;
  if (severity === "warning") return "white" as const;
  return "quiet" as const;
}

function formatEventType(value: SecurityEvent["event_type"]) {
  return value.replaceAll("_", " ");
}

function formatTimestamp(value: string) {
  return new Intl.DateTimeFormat("en", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
    timeZone: IST_TIME_ZONE,
  }).format(new Date(value));
}

export function LiveEventFeed() {
  const { events, status, warning, synced } = useSecurityEvents();
  const visible = events.slice(-MAX_VISIBLE).reverse();
  const hidden = events.length - visible.length;

  return (
    <Panel
      id="live-event-feed-title"
      title="Decision stream"
      className="min-h-72 lg:col-span-8"
      badge={
        <span className="border-hazard/25 rounded-cta flex items-center gap-2 border px-3 py-1.5 font-mono text-[0.65rem] font-semibold tracking-[0.14em] uppercase">
          <span
            aria-hidden="true"
            className={`size-1.5 rounded-full ${
              status === "open" ? "bg-mint animate-pulse" : "bg-ultraviolet"
            }`}
          />
          {statusLabels[status]}
        </span>
      }
    >
      <div aria-live="polite" className="flex flex-1 flex-col pt-5">
        {warning ? (
          <p className="border-ultraviolet rounded-tag text-muted mb-4 border px-3 py-2 font-mono text-[0.7rem] leading-5">
            {warning}
          </p>
        ) : null}

        {visible.length === 0 ? (
          <div className="grid flex-1 place-items-center py-10 text-center">
            <div className="max-w-xs">
              <p className="text-sm font-bold">
                {status === "unconfigured"
                  ? "No backend configured"
                  : synced
                    ? "No decisions recorded yet"
                    : "Connecting to the decision stream"}
              </p>
              <p className="text-meta mt-2 text-xs leading-5">
                {status === "unconfigured"
                  ? "Set NEXT_PUBLIC_BACKEND_ORIGIN and restart. This panel shows gateway and Guardian decisions only, never sample data."
                  : "Decisions appear here as the gateway and Guardian emit them."}
              </p>
            </div>
          </div>
        ) : (
          <>
            {/* The dashed spine is the StoryStream rail from the design spec:
                timestamps sit on the rail, the decision sits in the tile. */}
            <ol className="border-rule space-y-3 border-l border-dashed pl-4 sm:pl-6">
              {visible.map((event) => (
                <li
                  key={event.event_id}
                  className="grid gap-2 sm:grid-cols-[6.5rem_minmax(0,1fr)] sm:items-start sm:gap-4"
                >
                  <div className="flex items-center gap-2 sm:block sm:pt-4">
                    <time
                      dateTime={event.timestamp}
                      className="text-meta tnum block font-mono text-[0.7rem] tracking-[0.1em]"
                    >
                      {formatTimestamp(event.timestamp)}
                    </time>
                    <span className="mt-2 block w-fit">
                      <Tag tone={severityTone(event.severity)}>
                        {event.severity}
                      </Tag>
                    </span>
                  </div>

                  <article
                    className={`bg-canvas rounded-tile border p-4 sm:p-5 ${
                      event.severity === "blocked"
                        ? "border-mint"
                        : "border-hazard/15"
                    }`}
                  >
                    <h3 className="text-[1.05rem] leading-none font-bold capitalize">
                      {formatEventType(event.event_type)}
                    </h3>
                    <p className="text-meta mt-2 line-clamp-2 font-mono text-[0.72rem] leading-5 break-words">
                      {event.reason}
                    </p>
                  </article>
                </li>
              ))}
            </ol>

            <p className="text-meta mt-5 font-mono text-[0.65rem] tracking-[0.14em] uppercase">
              Showing {visible.length} of {events.length}
              {hidden > 0 ? ` / ${hidden} older held` : ""}
            </p>
          </>
        )}
      </div>
    </Panel>
  );
}
