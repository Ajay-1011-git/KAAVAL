import type { IncidentExplanation } from "@/lib/contracts";

export async function POST(request: Request) {
  const body: unknown = await request.json();
  if (!body || typeof body !== "object") {
    return Response.json({ detail: "Invalid request" }, { status: 422 });
  }

  const eventIds = (body as Record<string, unknown>).event_ids;
  if (
    !Array.isArray(eventIds) ||
    eventIds.length === 0 ||
    !eventIds.every((eventId) => typeof eventId === "string")
  ) {
    return Response.json({ detail: "Invalid event_ids" }, { status: 422 });
  }

  const explanation: IncidentExplanation = {
    incident_id: `fixture-${eventIds[0]}`,
    related_event_ids: eventIds,
    summary:
      "KAAVAL recorded a replay attempt and blocked the related request. The recorded reason was nonce_reused.",
    affected_user: "user-demo-01",
    affected_application: null,
    suggested_remediation: [
      "Invalidate the affected session and establish a new bound session before retrying.",
    ],
    generated_at: new Date().toISOString(),
  };

  return Response.json(explanation, {
    headers: {
      "Access-Control-Expose-Headers": "X-KAAVAL-Chronicle-Mode",
      "X-KAAVAL-Chronicle-Mode": "fallback",
    },
  });
}
