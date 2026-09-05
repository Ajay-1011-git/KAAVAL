"use client";

import { useMemo } from "react";

import { Panel, Tag } from "@/app/components/vergeUi";
import type { SecurityEvent } from "@/lib/contracts";
import { useSecurityEvents } from "@/lib/eventsClient";
import { useIncidentSelection } from "@/lib/incidentSelection";
import { groupSecurityEvents } from "@/lib/incidents";

// Same reasoning as the decision stream: the newest few incidents are the ones
// an operator acts on, and the count below states how many are held back.
const MAX_VISIBLE = 4;

function severityTone(severity: SecurityEvent["severity"]) {
  if (severity === "blocked") return "mint" as const;
  if (severity === "warning") return "white" as const;
  return "quiet" as const;
}

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
  const { selectedIncident, setSelectedIncident } = useIncidentSelection();
  const incidents = useMemo(() => groupSecurityEvents(events), [events]);
  const visible = incidents.slice(-MAX_VISIBLE).reverse();

  return (
    <Panel
      id="incident-timeline-title"
      title="Incidents"
      className="min-h-72 lg:col-span-5"
      badge={
        <Tag tone="quiet">{incidents.length} grouped</Tag>
      }
    >
      {visible.length === 0 ? (
        <div className="grid flex-1 place-items-center py-10 text-center">
          <div className="max-w-xs">
            <p className="text-sm font-bold">No incidents assembled yet</p>
            <p className="text-meta mt-2 text-xs leading-5">
              Related session or application events are grouped here within a
              five-minute window.
            </p>
          </div>
        </div>
      ) : (
        <>
          <ol className="mt-5 space-y-3">
            {visible.map((incident) => {
              const isSelected =
                selectedIncident?.incident_id === incident.incident_id;

              return (
                <li key={incident.incident_id}>
                  <button
                    type="button"
                    aria-expanded={isSelected}
                    onClick={() =>
                      setSelectedIncident(
                        isSelected
                          ? null
                          : {
                              incident_id: incident.incident_id,
                              event_ids: incident.events.map(
                                (event) => event.event_id,
                              ),
                            },
                      )
                    }
                    className={`bg-canvas rounded-tile w-full cursor-pointer border p-4 text-left transition-colors duration-150 ${
                      isSelected
                        ? "border-mint"
                        : "border-hazard/15 hover:border-hazard/45"
                    }`}
                  >
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <h3 className="text-[1.05rem] leading-none font-bold capitalize">
                        {incidentTitle(incident.events)}
                      </h3>
                      <Tag tone={severityTone(incident.severity)}>
                        {incident.severity}
                      </Tag>
                    </div>
                    <p className="text-meta tnum mt-3 font-mono text-[0.65rem] tracking-[0.1em]">
                      {incident.events.length} events / {formatTime(incident.started_at)}
                      {" to "}
                      {formatTime(incident.ended_at)} UTC
                    </p>
                  </button>

                  {isSelected ? (
                    <ol className="border-rule ml-4 space-y-3 border-l border-dashed py-4 pl-5">
                      {incident.events.map((event) => (
                        <li key={event.event_id}>
                          <div className="flex flex-wrap items-baseline justify-between gap-2">
                            <p className="text-sm font-bold capitalize">
                              {humanize(event.event_type)}
                            </p>
                            <time
                              dateTime={event.timestamp}
                              className="text-meta tnum font-mono text-[0.62rem]"
                            >
                              {formatTime(event.timestamp)} UTC
                            </time>
                          </div>
                          <p className="text-meta mt-1 font-mono text-[0.68rem] leading-5 break-words">
                            {event.reason}
                          </p>
                        </li>
                      ))}
                      <li className="text-meta font-mono text-[0.6rem] tracking-[0.14em] uppercase">
                        Correlation {incident.correlation_id}
                      </li>
                    </ol>
                  ) : null}
                </li>
              );
            })}
          </ol>

          <p className="text-meta mt-5 font-mono text-[0.65rem] tracking-[0.14em] uppercase">
            Showing {visible.length} of {incidents.length}
          </p>
        </>
      )}
    </Panel>
  );
}
