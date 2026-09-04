import type { IncidentExplanation } from "@/lib/contracts";

export type ChronicleMode = "live" | "fallback" | "unknown";

export interface ChronicleResult {
  explanation: IncidentExplanation;
  mode: ChronicleMode;
}

function isNullableString(value: unknown): value is string | null {
  return value === null || typeof value === "string";
}

function isStringArray(value: unknown): value is string[] {
  return (
    Array.isArray(value) &&
    value.every((item) => typeof item === "string" && item.trim().length > 0)
  );
}

export function isIncidentExplanation(
  value: unknown,
): value is IncidentExplanation {
  if (!value || typeof value !== "object") return false;

  const explanation = value as Record<string, unknown>;
  return (
    typeof explanation.incident_id === "string" &&
    isStringArray(explanation.related_event_ids) &&
    typeof explanation.summary === "string" &&
    explanation.summary.trim().length > 0 &&
    isNullableString(explanation.affected_user) &&
    isNullableString(explanation.affected_application) &&
    isStringArray(explanation.suggested_remediation) &&
    typeof explanation.generated_at === "string" &&
    !Number.isNaN(Date.parse(explanation.generated_at))
  );
}

function getChronicleUrl() {
  const backendOrigin = process.env.NEXT_PUBLIC_BACKEND_ORIGIN?.replace(
    /\/$/,
    "",
  );

  return backendOrigin
    ? `${backendOrigin}/chronicle/explain`
    : "/fixtures/chronicle";
}

export async function requestIncidentExplanation(
  eventIds: string[],
): Promise<ChronicleResult> {
  const response = await fetch(getChronicleUrl(), {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ event_ids: eventIds }),
  });

  if (!response.ok) {
    throw new Error(`Chronicle returned HTTP ${response.status}.`);
  }

  const payload: unknown = await response.json();
  if (!isIncidentExplanation(payload)) {
    throw new Error("Chronicle returned an explanation with an invalid shape.");
  }

  const returnedIds = new Set(payload.related_event_ids);
  if (
    returnedIds.size !== eventIds.length ||
    eventIds.some((eventId) => !returnedIds.has(eventId))
  ) {
    throw new Error("Chronicle returned an explanation for different events.");
  }

  const responseMode = response.headers.get("X-KAAVAL-Chronicle-Mode");
  const mode: ChronicleMode =
    responseMode === "live" || responseMode === "fallback"
      ? responseMode
      : "unknown";

  return { explanation: payload, mode };
}
