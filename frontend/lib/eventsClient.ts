"use client";

import {
  createContext,
  createElement,
  type ReactNode,
  useContext,
  useEffect,
  useState,
} from "react";

import type { SecurityEvent } from "@/lib/contracts";

const eventTypes = new Set<SecurityEvent["event_type"]>([
  "session_bound",
  "replay_attempted",
  "proof_absent",
  "signature_invalid",
  "request_blocked",
  "request_allowed",
  "oauth_grant_blocked",
  "oauth_grant_allowed",
  "device_code_blocked",
]);

const severities = new Set<SecurityEvent["severity"]>([
  "info",
  "warning",
  "blocked",
]);

export type EventStreamStatus = "connecting" | "open" | "reconnecting";

function isNullableString(value: unknown): value is string | null {
  return value === null || typeof value === "string";
}

function isStringRecord(value: unknown): value is Record<string, string> {
  return (
    !!value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.values(value).every((entry) => typeof entry === "string")
  );
}

export function isSecurityEvent(value: unknown): value is SecurityEvent {
  if (!value || typeof value !== "object") return false;

  const event = value as Record<string, unknown>;
  return (
    typeof event.event_id === "string" &&
    typeof event.timestamp === "string" &&
    !Number.isNaN(Date.parse(event.timestamp)) &&
    eventTypes.has(event.event_type as SecurityEvent["event_type"]) &&
    isNullableString(event.session_id) &&
    isNullableString(event.user_id) &&
    isNullableString(event.application_id) &&
    typeof event.reason === "string" &&
    isStringRecord(event.detail) &&
    severities.has(event.severity as SecurityEvent["severity"])
  );
}

function getEventsUrl() {
  const backendOrigin = process.env.NEXT_PUBLIC_BACKEND_ORIGIN?.replace(
    /\/$/,
    "",
  );

  return backendOrigin
    ? `${backendOrigin}/events/stream`
    : "/fixtures/events";
}

interface EventStreamState {
  events: SecurityEvent[];
  status: EventStreamStatus;
  warning: string | null;
}

const EventStreamContext = createContext<EventStreamState | null>(null);

function useEventStream(): EventStreamState {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [status, setStatus] = useState<EventStreamStatus>("connecting");
  const [warning, setWarning] = useState<string | null>(null);

  useEffect(() => {
    const source = new EventSource(getEventsUrl());

    source.onopen = () => {
      setStatus("open");
      setWarning(null);
    };

    // The real gateway (backend/gateway/events_stream.py) tags every frame
    // `event: security_event`, while the local /fixtures/events route emits
    // unnamed frames. EventSource.onmessage fires ONLY for unnamed frames, so
    // listening on just one of the two silently yields an empty feed against
    // the other. Both are wired to the same handler.
    const handleMessage = (message: MessageEvent<string>) => {
      try {
        const payload: unknown = JSON.parse(message.data);
        if (!isSecurityEvent(payload)) {
          setWarning("An event was ignored because it did not match the contract.");
          return;
        }

        setEvents((currentEvents) => {
          if (currentEvents.some((event) => event.event_id === payload.event_id)) {
            return currentEvents;
          }

          return [...currentEvents, payload].slice(-100);
        });
        setWarning(null);
      } catch {
        setWarning("An event was ignored because it was not valid JSON.");
      }
    };

    source.onmessage = handleMessage;
    source.addEventListener("security_event", handleMessage);

    source.onerror = () => {
      setStatus("reconnecting");
      setWarning("The event stream was interrupted. Reconnecting automatically…");
    };

    return () => {
      source.removeEventListener("security_event", handleMessage);
      source.close();
    };
  }, []);

  return { events, status, warning };
}

export function SecurityEventsProvider({ children }: { children: ReactNode }) {
  const streamState = useEventStream();

  return createElement(
    EventStreamContext.Provider,
    { value: streamState },
    children,
  );
}

export function useSecurityEvents(): EventStreamState {
  const streamState = useContext(EventStreamContext);
  if (!streamState) {
    throw new Error(
      "useSecurityEvents must be used within a SecurityEventsProvider.",
    );
  }

  return streamState;
}
