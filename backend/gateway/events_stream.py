# backend/gateway/events_stream.py
#
# T-RO.7: GET /events/stream — SSE stream of SecurityEvent rows as they're
# written (TRD §5, §7), resumable via a cursor so a reconnecting dashboard
# doesn't replay the whole history.
#
# SQLite has no native pub/sub, so this polls `rowid > cursor` on a short
# interval. That is deliberate: introducing Redis for this would violate
# the stack's GROUND TRUTH (PRD §4.2) for no benefit at demo scale.
#
# CURSOR NOTE: the TRD calls this `since_event_id`, and that is the public
# parameter name. `event_id` is a UUID and therefore not ordered, so the
# SQLite rowid of that event is used as the actual scan position. The two
# never disagree because rowid is monotonic for this append-only table.
#
# Each frame carries `id: <event_id>`, which is what a browser's
# EventSource echoes back as the `Last-Event-ID` header when it
# auto-reconnects — so Sai's dashboard resumes correctly after a dropped
# connection without any client-side bookkeeping.

import asyncio
import json
from typing import Optional

from fastapi import APIRouter, Header, Query
from fastapi.responses import JSONResponse
from sse_starlette.sse import EventSourceResponse

from backend.contracts import SecurityEvent
from backend.db import get_connection
from backend.events import get_events_since

router = APIRouter()

POLL_INTERVAL_SECONDS = 0.5

# Must match the page size get_events_since applies, so the stream can tell a
# partial page (backlog drained) from a full one (more history waiting).
EVENT_PAGE_SIZE = 100

# Emitted once, after the replayed history has been sent and before the first
# live poll. A first EventSource connection carries no Last-Event-ID, so the
# cursor is 0 and the whole recorded history is legitimately replayed; the
# dashboard needs it for the feed. But without a marker saying where that
# history stops, the client cannot tell a replayed event from one happening
# now, so its counters climb from zero on every reload and its attack banner
# fires for events that are hours old. This frame is that boundary.
SYNC_EVENT = "stream_synced"


class UnknownCursor(Exception):
    """The supplied since_event_id/Last-Event-ID isn't a known event."""


def resolve_cursor(since_event_id: Optional[str], last_event_id: Optional[str] = None) -> int:
    """Turn a client-supplied event_id into a rowid scan position.

    An explicit `?since_event_id=` wins over the `Last-Event-ID` header:
    the query param is a deliberate request, the header is a browser
    replaying whatever it saw last.

    No cursor at all means "from the beginning" — a first connection
    legitimately wants the history it missed.
    """
    cursor_event_id = since_event_id or last_event_id
    if not cursor_event_id:
        return 0

    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT rowid FROM events WHERE event_id = ?", (cursor_event_id,)
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        raise UnknownCursor(cursor_event_id)
    return row["rowid"]


def event_to_frame(event: SecurityEvent) -> dict:
    """One SSE frame carrying the full frozen SecurityEvent shape."""
    return {
        "event": "security_event",
        "id": event.event_id,
        "data": json.dumps(event.model_dump()),
    }


def sync_frame(replayed: int) -> dict:
    """The backlog/live boundary marker.

    Deliberately carries no `id:`. EventSource echoes the last id it saw as
    the Last-Event-ID header on reconnect, and this marker is not a row in
    the events table, so resolve_cursor would reject it as an unknown cursor
    and the reconnect would 400.
    """
    return {"event": SYNC_EVENT, "data": json.dumps({"replayed": replayed})}


async def event_stream(cursor: int = 0, poll_interval: float = POLL_INTERVAL_SECONDS):
    """Yield SSE frames for events written after `cursor`, forever.

    Infinite by design — the client disconnecting is what ends it.
    """
    synced = False
    replayed = 0

    while True:
        batch = get_events_since(cursor, limit=EVENT_PAGE_SIZE)
        for rowid, event in batch:
            cursor = rowid
            if not synced:
                replayed += 1
            yield event_to_frame(event)

        # A full page means there is more history behind it. Keep draining
        # without sleeping, so a long backlog does not trickle in one page
        # per poll interval.
        if len(batch) == EVENT_PAGE_SIZE:
            continue

        if not synced:
            synced = True
            yield sync_frame(replayed)

        await asyncio.sleep(poll_interval)


@router.get("/events/stream")
async def stream_events(
    since_event_id: Optional[str] = Query(default=None),
    last_event_id: Optional[str] = Header(default=None, alias="Last-Event-ID"),
):
    try:
        cursor = resolve_cursor(since_event_id, last_event_id)
    except UnknownCursor:
        # Loud, not silent. Streaming from the start would flood the
        # dashboard; streaming from the end would drop events. Neither is
        # detectable by the client, so the mismatch is reported instead
        # (PRD NFR-2: no unexplained behaviour).
        return JSONResponse(
            status_code=400,
            content={
                "detail": {
                    "reason": "unknown_since_event_id",
                    "hint": "reconnect without a cursor to resync from the start",
                }
            },
        )

    return EventSourceResponse(event_stream(cursor))
