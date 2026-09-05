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
  "device_code_allowed",
]);

const severities = new Set<SecurityEvent["severity"]>([
  "info",
  "warning",
  "blocked",
]);

export type EventStreamStatus =
  // No backend origin is configured, so there is nothing to connect to and
  // nothing to show. This is a distinct state from "connecting": the stream
  // will never open, and the dashboard must say so rather than sit on a
  // spinner or, as it used to, quietly render bundled fixtures instead.
  | "unconfigured"
  | "connecting"
  | "open"
  | "reconnecting";

// Emitted by the gateway once it has finished replaying recorded history and
// is about to go live. See backend/gateway/events_stream.py.
const SYNC_EVENT = "stream_synced";

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

function getEventsUrl(): string | null {
  const backendOrigin = process.env.NEXT_PUBLIC_BACKEND_ORIGIN?.replace(
    /\/$/,
    "",
  );

  // No fixture fallback. A dashboard that invents a stream when the real one
  // is missing is indistinguishable, on screen, from one showing real blocked
  // attacks — which is the exact unearned trust this project argues against.
  return backendOrigin ? `${backendOrigin}/events/stream` : null;
}

interface EventStreamState {
  events: SecurityEvent[];
  status: EventStreamStatus;
  warning: string | null;
  /** True once the gateway has finished replaying recorded history. */
  synced: boolean;
  /**
   * Index into `events` at which live traffic begins. Everything before it
   * was replayed history that the gateway had already recorded when this
   * page connected. Anything treating a replayed event as "happening now"
   * (an alert banner, a live counter) must read this.
   */
  liveFromIndex: number;
}

const EventStreamContext = createContext<EventStreamState | null>(null);

interface StreamData {
  events: SecurityEvent[];
  synced: boolean;
  liveFromIndex: number;
}

const EMPTY_DATA: StreamData = { events: [], synced: false, liveFromIndex: 0 };

function useEventStream(): EventStreamState {
  // events / synced / liveFromIndex live in one state object because the
  // boundary is defined *relative to* the event list: recording "live starts
  // here" needs the list length at that instant, which two separate useStates
  // cannot read consistently from inside an event handler.
  const [data, setData] = useState<StreamData>(EMPTY_DATA);
  const [status, setStatus] = useState<EventStreamStatus>(() =>
    getEventsUrl() ? "connecting" : "unconfigured",
  );
  const [warning, setWarning] = useState<string | null>(null);

  useEffect(() => {
    const url = getEventsUrl();
    if (!url) return;

    const source = new EventSource(url);

    source.onopen = () => {
      setStatus("open");
      setWarning(null);
    };

    // The real gateway (backend/gateway/events_stream.py) tags every frame
    // `event: security_event`, and marks the end of the replayed history with
    // a single `event: stream_synced` frame.
    const handleMessage = (message: MessageEvent<string>) => {
      try {
        const payload: unknown = JSON.parse(message.data);
        if (!isSecurityEvent(payload)) {
          setWarning("An event was ignored because it did not match the contract.");
          return;
        }

        setData((current) => {
          if (current.events.some((event) => event.event_id === payload.event_id)) {
            return current;
          }

          return {
            ...current,
            events: [...current.events, payload].slice(-100),
          };
        });
        setWarning(null);
      } catch {
        setWarning("An event was ignored because it was not valid JSON.");
      }
    };

    const handleSync = () => {
      setData((current) => {
        // Only the first sync sets the boundary. A later one follows a
        // reconnect, and the events it replays are ones this dashboard missed
        // while it was open — recent enough to still count as live.
        if (current.synced) return current;
        return {
          ...current,
          synced: true,
          liveFromIndex: current.events.length,
        };
      });
    };

    source.onmessage = handleMessage;
    source.addEventListener("security_event", handleMessage);
    source.addEventListener(SYNC_EVENT, handleSync);

    source.onerror = () => {
      setStatus("reconnecting");
      setWarning("The event stream was interrupted. Reconnecting automatically…");
    };

    return () => {
      source.removeEventListener("security_event", handleMessage);
      source.removeEventListener(SYNC_EVENT, handleSync);
      source.close();
    };
  }, []);

  return { ...data, status, warning };
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
