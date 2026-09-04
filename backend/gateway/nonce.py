# backend/gateway/nonce.py
#
# T-RO.4: POST /auth/nonce — issues a single-use, short-lived nonce tied
# to the requesting session. Also exposes `consume_nonce`, the function
# T-RO.5's signature-verification path calls to perform check 5 of the
# seven-step order (TRD §6.1): "nonce was issued by the server and is
# unused."
#
# `secrets.token_urlsafe` is stdlib and its signature was confirmed
# in-session before use (per the ANTI-HALLUCINATION RULES) rather than
# assumed.

import os
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.db import get_connection

router = APIRouter()

NONCE_TTL_SECONDS = int(os.environ.get("NONCE_TTL_SECONDS", "30"))

# --- Local schema (scoped to this file, same pattern as webauthn_routes.py). ---
_SCHEMA = """
CREATE TABLE IF NOT EXISTS nonces (
    nonce       TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL,
    issued_at   TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    used        INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_nonces_session_id ON nonces (session_id);
"""


def _ensure_schema() -> None:
    conn = get_connection()
    try:
        conn.executescript(_SCHEMA)
        conn.commit()
    finally:
        conn.close()


_ensure_schema()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


class NonceRequest(BaseModel):
    session_id: str


@router.post("/auth/nonce")
def issue_nonce(body: NonceRequest):
    conn = get_connection()
    try:
        session_row = conn.execute(
            "SELECT is_active FROM sessions WHERE session_id = ?", (body.session_id,)
        ).fetchone()
    finally:
        conn.close()

    if session_row is None or session_row["is_active"] != 1:
        raise HTTPException(status_code=400, detail="unknown_or_inactive_session")

    nonce_value = secrets.token_urlsafe(32)
    issued_at = _now()
    expires_at = issued_at + timedelta(seconds=NONCE_TTL_SECONDS)

    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO nonces (nonce, session_id, issued_at, expires_at, used) VALUES (?, ?, ?, ?, 0)",
            (nonce_value, body.session_id, _iso(issued_at), _iso(expires_at)),
        )
        conn.commit()
    finally:
        conn.close()

    return {"nonce": nonce_value, "issued_at": _iso(issued_at)}


def consume_nonce(nonce_value: str, session_id: str) -> bool:
    """Atomically mark a nonce as used, iff it exists, is unused, unexpired,
    and belongs to the given session. Returns True iff accepted (and now
    consumed); False otherwise.

    A nonce is never reusable even if verification later fails for a
    different reason — this function marks it used the moment it's
    looked at here, not only on a fully successful request. Callers
    (T-RO.5's verify_request) must call this exactly once per request, at
    the point of the actual check, not speculatively or more than once.
    """
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT session_id, expires_at, used FROM nonces WHERE nonce = ?",
            (nonce_value,),
        ).fetchone()

        if row is None or row["used"] == 1 or row["session_id"] != session_id:
            return False
        if _iso(_now()) > row["expires_at"]:
            return False

        cur = conn.execute(
            "UPDATE nonces SET used = 1 WHERE nonce = ? AND used = 0", (nonce_value,)
        )
        conn.commit()
        return cur.rowcount == 1
    finally:
        conn.close()
