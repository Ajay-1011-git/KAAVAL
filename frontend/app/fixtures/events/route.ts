import type { SecurityEvent } from "@/lib/contracts";

export const dynamic = "force-dynamic";

const fixtureEvents: SecurityEvent[] = [
  {
    event_id: "10000000-0000-4000-8000-000000000001",
    timestamp: "2026-09-04T16:05:00Z",
    event_type: "session_bound",
    session_id: "session-demo-01",
    user_id: "user-demo-01",
    application_id: null,
    reason: "session_key_bound",
    detail: { mode: "pulselock" },
    severity: "info",
  },
  {
    event_id: "10000000-0000-4000-8000-000000000002",
    timestamp: "2026-09-04T16:05:04Z",
    event_type: "replay_attempted",
    session_id: "session-demo-01",
    user_id: "user-demo-01",
    application_id: null,
    reason: "nonce_reused",
    detail: { path: "/api/transfer" },
    severity: "warning",
  },
  {
    event_id: "10000000-0000-4000-8000-000000000003",
    timestamp: "2026-09-04T16:05:04Z",
    event_type: "request_blocked",
    session_id: "session-demo-01",
    user_id: "user-demo-01",
    application_id: null,
    reason: "nonce_reused",
    detail: { path: "/api/transfer", decision: "blocked" },
    severity: "blocked",
  },
];

export async function GET(request: Request) {
  const encoder = new TextEncoder();
  let eventIndex = 0;
  let timer: ReturnType<typeof setInterval> | undefined;

  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(encoder.encode("retry: 1000\n\n"));

      timer = setInterval(() => {
        const event = fixtureEvents[eventIndex];
        if (event) {
          controller.enqueue(
            encoder.encode(
              `id: ${event.event_id}\ndata: ${JSON.stringify(event)}\n\n`,
            ),
          );
          eventIndex += 1;
          return;
        }

        controller.enqueue(encoder.encode(": keep-alive\n\n"));
      }, 250);

      request.signal.addEventListener(
        "abort",
        () => {
          if (timer) clearInterval(timer);
        },
        { once: true },
      );
    },
    cancel() {
      if (timer) clearInterval(timer);
    },
  });

  return new Response(stream, {
    headers: {
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "Content-Type": "text/event-stream; charset=utf-8",
    },
  });
}
