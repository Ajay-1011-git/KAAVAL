# backend/events.py — Stage 0
#
# Shared, canonical: every module (gateway, guardian) writes SecurityEvent
# rows here via `write_event`. This is the single event bus for the whole
# system (TRD §6.2) — do not create a second events table or a parallel
# event shape, and do not redefine `write_event` a second time anywhere
# else. Other modules may call this function; only Rohith's gateway owns
# this file.

import json

from backend.contracts import SecurityEvent
from backend.db import get_connection


def write_event(event: SecurityEvent) -> SecurityEvent:
    """Persist a SecurityEvent row. Returns the event that was written."""
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO events (
                event_id, timestamp, event_type, session_id, user_id,
                application_id, reason, detail, severity
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.event_id,
                event.timestamp,
                event.event_type,
                event.session_id,
                event.user_id,
                event.application_id,
                event.reason,
                json.dumps(event.detail),
                event.severity,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return event


def get_events_since(since_cursor: int = 0, limit: int = 100) -> list[tuple[int, SecurityEvent]]:
    """Return events with rowid > since_cursor, oldest first, as (rowid, event) pairs.

    `event_id` (a UUID) is not itself ordered, so the SQLite `rowid` is used
    as the actual polling cursor. Used by the SSE stream
    (backend/gateway/events_stream.py) to poll for newly-written rows
    rather than replaying full history on every request (TRD §7).
    """
    conn = get_connection()
    try:
        rows = conn.execute(
            """
            SELECT rowid, event_id, timestamp, event_type, session_id, user_id,
                   application_id, reason, detail, severity
            FROM events
            WHERE rowid > ?
            ORDER BY rowid ASC
            LIMIT ?
            """,
            (since_cursor, limit),
        ).fetchall()
    finally:
        conn.close()

    events = []
    for row in rows:
        events.append(
            (
                row["rowid"],
                SecurityEvent(
                    event_id=row["event_id"],
                    timestamp=row["timestamp"],
                    event_type=row["event_type"],
                    session_id=row["session_id"],
                    user_id=row["user_id"],
                    application_id=row["application_id"],
                    reason=row["reason"],
                    detail=json.loads(row["detail"]),
                    severity=row["severity"],
                ),
            )
        )
    return events
