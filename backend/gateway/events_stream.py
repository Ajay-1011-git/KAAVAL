# backend/gateway/events_stream.py
#
# GET /events/stream — SSE stream of SecurityEvent rows as they're written
# (TRD §5, §7). Polls the events table with a `since` rowid cursor rather
# than replaying full history on every connection.
#
# A minimal working version is stood up here in Stage 0 so the rest of the
# team has a real endpoint to integrate against from the start; T-RO.7
# hardens/extends it further.

import asyncio
import json

from fastapi import APIRouter
from sse_starlette.sse import EventSourceResponse

from backend.events import get_events_since

router = APIRouter()

POLL_INTERVAL_SECONDS = 0.5


@router.get("/events/stream")
async def stream_events():
    async def event_generator():
        cursor = 0
        while True:
            rows = get_events_since(cursor)
            for rowid, event in rows:
                cursor = rowid
                yield {"event": "security_event", "data": json.dumps(event.model_dump())}
            await asyncio.sleep(POLL_INTERVAL_SECONDS)

    return EventSourceResponse(event_generator())
