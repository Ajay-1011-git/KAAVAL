# MINIMAL STAND-IN for Rohith's Stage 0 scaffold (Team Integration Plan §3).
# SQLite connection + schema migration for the shared `events` and `sessions` tables.

import os
import sqlite3
from contextlib import contextmanager

DATABASE_PATH = os.environ.get("DATABASE_URL", "sqlite:///./kaaval.db").replace("sqlite:///", "")

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    session_id TEXT,
    user_id TEXT,
    application_id TEXT,
    reason TEXT NOT NULL,
    detail TEXT NOT NULL,
    severity TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_session_id ON events(session_id);

CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    user_id TEXT,
    public_key_jwk TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    last_sequence INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
"""


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_connection()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


@contextmanager
def db_session():
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()
