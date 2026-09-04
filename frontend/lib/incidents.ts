import type { SecurityEvent } from "@/lib/contracts";

export const INCIDENT_WINDOW_MS = 5 * 60 * 1000;

export interface SecurityIncident {
  incident_id: string;
  correlation_id: string;
  events: SecurityEvent[];
  started_at: string;
  ended_at: string;
  severity: SecurityEvent["severity"];
}

const severityRank: Record<SecurityEvent["severity"], number> = {
  info: 0,
  warning: 1,
  blocked: 2,
};

function getCorrelationKeys(event: SecurityEvent) {
  return [event.session_id, event.application_id].filter(
    (value): value is string => Boolean(value),
  );
}

function sharesCorrelationKey(
  incident: SecurityIncident,
  event: SecurityEvent,
) {
  const eventKeys = getCorrelationKeys(event);
  if (eventKeys.length === 0) return false;

  return incident.events.some((incidentEvent) => {
    const incidentKeys = getCorrelationKeys(incidentEvent);
    return eventKeys.some((key) => incidentKeys.includes(key));
  });
}

function highestSeverity(
  current: SecurityEvent["severity"],
  candidate: SecurityEvent["severity"],
) {
  return severityRank[candidate] > severityRank[current] ? candidate : current;
}

export function groupSecurityEvents(
  events: SecurityEvent[],
  windowMs = INCIDENT_WINDOW_MS,
): SecurityIncident[] {
  const sortedEvents = [...events].sort(
    (left, right) =>
      Date.parse(left.timestamp) - Date.parse(right.timestamp),
  );
  const incidents: SecurityIncident[] = [];

  for (const event of sortedEvents) {
    const eventTime = Date.parse(event.timestamp);
    const matchingIncident = [...incidents]
      .reverse()
      .find((incident) => {
        const elapsed = eventTime - Date.parse(incident.ended_at);
        return (
          elapsed >= 0 &&
          elapsed <= windowMs &&
          sharesCorrelationKey(incident, event)
        );
      });

    if (!matchingIncident) {
      const correlationId =
        event.session_id ?? event.application_id ?? event.event_id;
      incidents.push({
        incident_id: `incident-${event.event_id}`,
        correlation_id: correlationId,
        events: [event],
        started_at: event.timestamp,
        ended_at: event.timestamp,
        severity: event.severity,
      });
      continue;
    }

    matchingIncident.events.push(event);
    matchingIncident.ended_at = event.timestamp;
    matchingIncident.severity = highestSeverity(
      matchingIncident.severity,
      event.severity,
    );
  }

  return incidents;
}
