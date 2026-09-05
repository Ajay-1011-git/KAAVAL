# backend/gateway/demo_app_routes.py
#
# T-RO.6: the demo application — one action (/api/transfer), two modes.
#
#   baseline  — accepts a plain session cookie, no signature required.
#               This is a REQUIRED negative control (PRD FR-14): the
#               captured cookie really does work, so the vulnerability is
#               demonstrated rather than asserted.
#   protected — requires a valid X-KAAVAL-Proof envelope, verified by the
#               seven checks in verify.py (T-RO.5).
#
# The mode selects HOW THE REQUEST IS AUTHORISED, never what the action does —
# otherwise the demo's before/after would be comparing two different things.
# Both paths run the same _execute_transfer().
#
# HOW THE MODE IS CHOSEN (updated for the honest two-laptop demo):
#   * An explicit ?mode=baseline|protected is an OVERRIDE, kept for the unit
#     tests and any legacy caller. KAAVAL_DEFAULT_MODE is retained as a
#     documented env knob but is no longer the implicit fallback.
#   * With NO ?mode= (what the real demo clients send), the request's real
#     authorisation is decided by the SESSION's own PulseLock enrollment
#     (demo_pulselock_sessions), never by the caller. This is what makes one
#     attacker action genuinely succeed before the victim enables PulseLock and
#     genuinely fail after — see the transfer handler and /api/protection/*.
#   The caller never gets to pick its own security posture, which the old
#   attacker-chosen ?mode= let it do — a dishonesty this removes.
#
# CONTRACT NOTE (flagged, not changed): the frozen SignedRequestEnvelope
# (TRD §6.1) covers path but not the query string, so `?mode=` is outside
# the signature. That's why the default mode is server-side config and
# the param is understood as a demo affordance. Extending the canonical
# string to cover the query string would be a change to a frozen
# contract — a whole-team decision, not a local edit.

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from backend.contracts import SecurityEvent
from backend.db import get_connection
from backend.events import write_event
from backend.gateway.verify import ActualRequest, verify_proof
from backend.gateway.webauthn_routes import SESSION_COOKIE_NAME

router = APIRouter()

DEFAULT_MODE = os.environ.get("KAAVAL_DEFAULT_MODE", "protected")

# --- Local schema (scoped to this file, same pattern as the other
# gateway modules). Purely demo-application state. ---
_SCHEMA = """
CREATE TABLE IF NOT EXISTS demo_transfers (
    transfer_id  TEXT PRIMARY KEY,
    session_id   TEXT,
    user_id      TEXT,
    to_account   TEXT NOT NULL,
    amount       INTEGER NOT NULL,
    mode         TEXT NOT NULL,   -- "baseline" | "protected"
    created_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_demo_transfers_session_id ON demo_transfers (session_id);

-- Per-session PulseLock enrollment (the honest two-laptop demo). A row here
-- means the victim turned PulseLock ON for THIS session: from then on a bare
-- cookie is no longer accepted for it (a proof is required), while sessions
-- that never enrolled still behave as baseline. This is what lets one attacker
-- action genuinely succeed before enrollment and genuinely fail after it,
-- rather than the caller dictating the mode via a query param.
CREATE TABLE IF NOT EXISTS demo_pulselock_sessions (
    session_id   TEXT PRIMARY KEY,
    enrolled_at  TEXT NOT NULL
);
"""


def _ensure_schema() -> None:
    conn = get_connection()
    try:
        conn.executescript(_SCHEMA)
        conn.commit()
    finally:
        conn.close()


_ensure_schema()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _reject(reason: str, *, status_code: int = 401, failed_check: Optional[int] = None):
    """Structured rejection — never a bare 500 for an expected failure."""
    return JSONResponse(
        status_code=status_code,
        content={"detail": {"reason": reason, "failed_check": failed_check}},
    )


def _lookup_active_session(session_id: str) -> Optional[dict]:
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT session_id, user_id, is_active FROM sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone()
    finally:
        conn.close()
    if row is None or row["is_active"] != 1:
        return None
    return dict(row)


def _execute_transfer(payload: dict, session_id: Optional[str], user_id: Optional[str], mode: str) -> dict:
    """The actual application action. Identical in both modes."""
    transfer_id = uuid.uuid4().hex
    to_account = str(payload.get("to_account", ""))
    amount = int(payload.get("amount", 0))

    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO demo_transfers (transfer_id, session_id, user_id, to_account, amount, mode, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (transfer_id, session_id, user_id, to_account, amount, mode, _now()),
        )
        conn.commit()
    finally:
        conn.close()

    return {
        "status": "ok",
        "mode": mode,
        "transfer_id": transfer_id,
        "to_account": to_account,
        "amount": amount,
    }


def _is_pulselock_enrolled(session_id: Optional[str]) -> bool:
    """True if the victim turned PulseLock ON for this specific session."""
    if not session_id:
        return False
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT 1 FROM demo_pulselock_sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone()
    finally:
        conn.close()
    return row is not None


@router.post("/api/transfer")
async def transfer(request: Request, mode: Optional[str] = None):
    # Raw bytes, not parsed JSON: body_hash is defined over the exact
    # bytes received (TRD §6.1), so re-serializing would change the hash.
    raw_body = await request.body()

    # An explicit ?mode= is an override kept for the unit tests and any legacy
    # caller: it forces one path regardless of enrollment. The demo clients
    # (attacker console, victim page) send NO mode, so the request's real
    # authorisation is decided below — by the session's own PulseLock state,
    # never by the caller.
    if mode is not None:
        active_mode = mode.lower()
        if active_mode not in ("baseline", "protected"):
            return _reject("unknown_mode", status_code=400)
        if active_mode == "baseline":
            return _baseline_transfer(request, raw_body)
        return _protected_transfer(request, raw_body)

    # No explicit mode — the honest path.
    #   * A signed request (proof present) is always verified: the victim's
    #     own requests after enrolling take this path and succeed.
    #   * A cookie-only request is accepted UNLESS this session has enrolled in
    #     PulseLock. Before enrollment a stolen cookie works (the vulnerability);
    #     after enrollment the identical request is refused as proof_absent —
    #     and _protected_transfer(verify_proof(None, ...)) emits exactly that
    #     block event, so the same code path and the same dashboard signal are
    #     reused rather than duplicated.
    if request.headers.get("x-kaaval-proof"):
        return _protected_transfer(request, raw_body)

    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if _is_pulselock_enrolled(session_id):
        return _protected_transfer(request, raw_body)
    return _baseline_transfer(request, raw_body)


@router.get("/api/protection")
async def protection_state(request: Request):
    """Current PulseLock enrollment for the caller's session cookie. The
    attacker console polls this (with the stolen cookie) to watch the victim's
    session flip from unprotected to protected in real time."""
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    return {
        "pulselock": _is_pulselock_enrolled(session_id),
        "session_present": bool(session_id),
    }


@router.post("/api/protection/enable")
async def enable_pulselock(request: Request):
    """The victim turns PulseLock ON for their own session. Idempotent."""
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_id:
        return _reject("no_session_cookie")
    session = _lookup_active_session(session_id)
    if session is None:
        return _reject("unknown_or_inactive_session")

    conn = get_connection()
    try:
        conn.execute(
            "INSERT OR IGNORE INTO demo_pulselock_sessions (session_id, enrolled_at) VALUES (?, ?)",
            (session_id, _now()),
        )
        conn.commit()
    finally:
        conn.close()

    write_event(
        SecurityEvent(
            event_id=uuid.uuid4().hex,
            timestamp=_now(),
            event_type="session_bound",
            session_id=session_id,
            user_id=session["user_id"],
            application_id=None,
            reason="pulselock_enabled",
            detail={"action": "enable_pulselock", "path": "/api/protection/enable"},
            severity="info",
        )
    )
    return {"status": "ok", "pulselock": True}


@router.post("/api/protection/disable")
async def disable_pulselock(request: Request):
    """Demo reset so the before/after can be replayed without wiping the DB.
    Un-enrolls the caller's session from PulseLock."""
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_id:
        return _reject("no_session_cookie")
    conn = get_connection()
    try:
        conn.execute(
            "DELETE FROM demo_pulselock_sessions WHERE session_id = ?",
            (session_id,),
        )
        conn.commit()
    finally:
        conn.close()
    return {"status": "ok", "pulselock": False}


def _parse_body(raw_body: bytes) -> Optional[dict]:
    try:
        parsed = json.loads(raw_body or b"{}")
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _baseline_transfer(request: Request, raw_body: bytes):
    """Unprotected: whoever holds the cookie is trusted. That is the point."""
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_id:
        return _reject("no_session_cookie")

    session = _lookup_active_session(session_id)
    if session is None:
        return _reject("unknown_or_inactive_session")

    payload = _parse_body(raw_body)
    if payload is None:
        return _reject("malformed_body", status_code=400)

    result = _execute_transfer(payload, session_id, session["user_id"], "baseline")

    # Recorded so the dashboard timeline can show the attack succeeding in
    # the "before" scene. severity is "warning", not "info": this request
    # was allowed only because proof-of-possession was switched off.
    write_event(
        SecurityEvent(
            event_id=uuid.uuid4().hex,
            timestamp=_now(),
            event_type="request_allowed",
            session_id=session_id,
            user_id=session["user_id"],
            application_id=None,
            reason="baseline_mode_no_proof_required",
            detail={"mode": "baseline", "path": "/api/transfer", "transfer_id": result["transfer_id"]},
            severity="warning",
        )
    )
    return result


def _protected_transfer(request: Request, raw_body: bytes):
    """PulseLock-protected: the cookie proves nothing; the signature does."""
    actual = ActualRequest(
        method=request.method,
        origin=request.headers.get("origin", ""),
        path=request.url.path,
        body=raw_body,
    )

    result = verify_proof(request.headers.get("x-kaaval-proof"), actual)
    if not result.ok:
        # verify_proof already wrote the SecurityEvent naming the exact
        # failed check — don't write a second, vaguer one here.
        return _reject(result.reason, failed_check=result.failed_check)

    payload = _parse_body(raw_body)
    if payload is None:
        return _reject("malformed_body", status_code=400)

    envelope_session_id = result.event.session_id if result.event else None
    session = _lookup_active_session(envelope_session_id) if envelope_session_id else None
    user_id = session["user_id"] if session else None

    return _execute_transfer(payload, envelope_session_id, user_id, "protected")
