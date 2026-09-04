"use client";

import { useMemo, useState } from "react";

import type { SecurityEvent } from "@/lib/contracts";
import { useSecurityEvents } from "@/lib/eventsClient";
import { groupSecurityEvents } from "@/lib/incidents";

const severityStyles: Record<SecurityEvent["severity"], string> = {
  info: "border-sky-300/20 bg-sky-300/10 text-sky-200",
  warning: "border-amber-300/20 bg-amber-300/10 text-amber-200",
  blocked: "border-rose-300/25 bg-rose-300/10 text-rose-200",
};

const timelineDotStyles: Record<SecurityEvent["severity"], string> = {
  info: "border-sky-300 bg-sky-300/20",
  warning: "border-amber-300 bg-amber-300/20",
  blocked: "border-rose-300 bg-rose-300/20",
};

function humanize(value: string) {
  return value.replaceAll("_", " ");
}

function formatTime(value: string) {
  return new Intl.DateTimeFormat("en", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
    timeZone: "UTC",
  }).format(new Date(value));
}

function incidentTitle(events: SecurityEvent[]) {
  const lastEvent = events.at(-1);
  return lastEvent ? humanize(lastEvent.event_type) : "Security incident";
}

export function IncidentTimeline() {
  const { events } = useSecurityEvents();
  const incidents = useMemo(() => groupSecurityEvents(events), [events]);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(
    null,
  );

  return (
    <section
      aria-labelledby="incident-timeline-title"
      className="flex min-h-72 flex-col rounded-2xl border border-white/10 bg-slate-900/70 p-5 shadow-2xl shadow-black/10 sm:p-6 lg:col-span-7"
    >
      <div className="flex items-start justify-between gap-4 border-b border-white/10 pb-4">
        <div>
          <p className="text-[0.68rem] font-semibold tracking-[0.2em] text-emerald-300 uppercase">
            Incident context
          </p>
          <h2
            id="incident-timeline-title"
            className="mt-2 text-xl font-semibold tracking-tight text-white"
          >
            Incident timeline
          </h2>
        </div>
        <span className="rounded-full border border-white/10 bg-white/5 px-2.5 py-1 text-[0.65rem] font-semibold text-slate-400">
          {incidents.length} {incidents.length === 1 ? "incident" : "incidents"}
        </span>
      </div>

      {incidents.length === 0 ? (
        <div className="grid flex-1 place-items-center py-10 text-center">
          <div className="max-w-xs">
            <span
              aria-hidden="true"
              className="mx-auto mb-4 block size-10 rounded-full border border-dashed border-slate-600 bg-slate-950/50"
            />
            <p className="text-sm font-medium text-slate-300">
              No incidents assembled yet
            </p>
            <p className="mt-2 text-xs leading-5 text-slate-500">
              Related session or application events will be grouped here within
              a five-minute window.
            </p>
          </div>
        </div>
      ) : (
        <ol className="mt-4 space-y-3">
          {incidents.map((incident, index) => {
            const isSelected = selectedIncidentId === incident.incident_id;

            return (
              <li key={incident.incident_id}>
                <button
                  type="button"
                  aria-expanded={isSelected}
                  onClick={() =>
                    setSelectedIncidentId((current) =>
                      current === incident.incident_id
                        ? null
                        : incident.incident_id,
                    )
                  }
                  className={`w-full rounded-xl border p-4 text-left transition focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-300 ${
                    isSelected
                      ? "border-emerald-300/30 bg-emerald-300/[0.06]"
                      : "border-white/10 bg-white/[0.025] hover:bg-white/[0.045]"
                  }`}
                >
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <p className="text-[0.65rem] font-semibold tracking-wide text-slate-500 uppercase">
                        Incident {String(index + 1).padStart(2, "0")}
                      </p>
                      <h3 className="mt-1 text-sm font-semibold text-white capitalize">
                        {incidentTitle(incident.events)}
                      </h3>
                    </div>
                    <span
                      className={`rounded-full border px-2 py-1 text-[0.65rem] font-semibold uppercase ${severityStyles[incident.severity]}`}
                    >
                      {incident.severity}
                    </span>
                  </div>

                  <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-[0.68rem] text-slate-500">
                    <span>{incident.events.length} events</span>
                    <span className="font-mono">
                      {incident.correlation_id}
                    </span>
                    <span>
                      {formatTime(incident.started_at)}–
                      {formatTime(incident.ended_at)} UTC
                    </span>
                  </div>
                </button>

                {isSelected ? (
                  <ol className="relative ml-5 border-l border-white/10 py-3 pl-5">
                    {incident.events.map((event) => (
                      <li
                        key={event.event_id}
                        className="relative py-2 first:pt-0 last:pb-0"
                      >
                        <span
                          aria-hidden="true"
                          className={`absolute top-3 -left-[1.56rem] size-3 rounded-full border-2 ${timelineDotStyles[event.severity]} first:top-1`}
                        />
                        <div className="flex flex-wrap items-baseline justify-between gap-2">
                          <p className="text-xs font-semibold text-slate-200 capitalize">
                            {humanize(event.event_type)}
                          </p>
                          <time
                            dateTime={event.timestamp}
                            className="font-mono text-[0.65rem] text-slate-500"
                          >
                            {formatTime(event.timestamp)} UTC
                          </time>
                        </div>
                        <p className="mt-1 font-mono text-[0.68rem] text-slate-400">
                          {event.reason}
                        </p>
                      </li>
                    ))}
                  </ol>
                ) : null}
              </li>
            );
          })}
        </ol>
      )}
    </section>
  );
}
