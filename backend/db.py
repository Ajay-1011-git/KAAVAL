# backend/db.py — Stage 0
#
# SQLite connection + schema migration. In-process state only, no Redis or
# other distributed infrastructure (PRD §4.2, TRD's stack justification).
#
# Owned by Rohith (gateway core). Other modules import `get_connection()`
# and `init_db()` from here rather than opening their own connections to a
# different file.

import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

_SQLITE_PREFIX = "sqlite:///"
_DEFAULT_DATABASE_URL = "sqlite:///./kaaval.db"


def get_db_path() -> str:
    """Resolve the SQLite file path from DATABASE_URL, on every call.

    Deliberately NOT resolved at import time. When this was a module-level
    constant, the first module in a process to import backend.db froze the
    path for everything that followed, so a test (or any second environment)
    that set DATABASE_URL afterwards was silently ignored and quietly shared
    another module's database.
    """
    database_url = os.environ.get("DATABASE_URL") or _DEFAULT_DATABASE_URL
    if database_url.startswith(_SQLITE_PREFIX):
        return database_url[len(_SQLITE_PREFIX):]
    # Fall back to treating the whole value as a plain filesystem path.
    return database_url


def get_connection() -> sqlite3.Connection:
    """Open a new connection to the KAAVAL SQLite database.

    Each caller owns the connection it opens (SQLite connections are not
    safe to share across threads/async tasks in this driver mode).
    """
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id        TEXT PRIMARY KEY,
    timestamp       TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    session_id      TEXT,
    user_id         TEXT,
    application_id  TEXT,
    reason          TEXT NOT NULL,
    detail          TEXT NOT NULL,  -- JSON-serialized dict
    severity        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_session_id ON events (session_id);
CREATE INDEX IF NOT EXISTS idx_events_event_id ON events (event_id);

CREATE TABLE IF NOT EXISTS sessions (
    session_id      TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL,
    public_key_jwk  TEXT NOT NULL,  -- JSON-serialized JWK, the bound session public key
    credential_id   TEXT,           -- WebAuthn passkey credential id, if applicable
    is_active       INTEGER NOT NULL DEFAULT 1,
    last_sequence   INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id);
"""


def init_db() -> None:
    """Create the `events` and `sessions` tables if they don't already exist."""
    Path(get_db_path()).parent.mkdir(parents=True, exist_ok=True)
    conn = get_connection()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


@contextmanager
def db_session():
    """Transactional wrapper around `get_connection()`.

    Commits on clean exit, always closes. Modules that only read (Chronicle)
    or that write a single row (Guardian, Radar) use this instead of managing
    commit/close by hand; the gateway's hot paths still use `get_connection()`
    directly where they need finer control over the transaction.
    """
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()
