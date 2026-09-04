# MINIMAL STAND-IN for Rohith's Stage 0 scaffold (Team Integration Plan §3).
# Shared write_event() helper. Every module that writes a SecurityEvent calls
# this — do not redefine it locally in radar/ or guardian/.

import json

from backend.contracts import SecurityEvent
from backend.db import db_session


def write_event(event: SecurityEvent) -> None:
    with db_session() as conn:
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
