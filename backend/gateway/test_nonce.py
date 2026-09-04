# backend/gateway/test_nonce.py
#
# T-RO.4 VERIFY: a nonce is issued, is accepted once, and is rejected on
# a second use.
#
# DATABASE_URL is set once at module import time, before backend.db (or
# anything importing it) is first imported in this process — see the note
# in test_webauthn_routes.py for why this must happen before, not inside,
# a test function.

import os
import tempfile
import uuid
from datetime import datetime, timedelta, timezone

_TEST_DB_DIR = tempfile.mkdtemp(prefix="kaaval_test_nonce_")
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_TEST_DB_DIR}/test_kaaval.db")

# Deliberately NOT setting NONCE_TTL_SECONDS here. nonce.py reads it into
# a module-level constant at import time, so a test module that sets it
# only wins if it happens to be imported first — which makes the whole
# suite order-dependent (and green locally, red on a teammate's machine).
# The expiry test below drives the stored expires_at directly instead.

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from backend.db import init_db, get_connection  # noqa: E402
from backend.gateway.nonce import router, consume_nonce, NONCE_TTL_SECONDS  # noqa: E402

init_db()

app = FastAPI()
app.include_router(router)
client = TestClient(app)


def _insert_session(session_id: str, is_active: int = 1) -> None:
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO sessions (session_id, user_id, public_key_jwk, credential_id, is_active, last_sequence, created_at)
            VALUES (?, 'test-user', '{}', NULL, ?, 0, ?)
            """,
            (session_id, is_active, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
    finally:
        conn.close()


def test_nonce_issued_once_accepted_once_rejected_on_reuse():
    session_id = uuid.uuid4().hex
    _insert_session(session_id)

    resp = client.post("/auth/nonce", json={"session_id": session_id})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "nonce" in body and "issued_at" in body
    nonce_value = body["nonce"]
    print("ISSUED NONCE:", body)

    first_use = consume_nonce(nonce_value, session_id)
    assert first_use is True, "first use of a fresh nonce must be accepted"

    second_use = consume_nonce(nonce_value, session_id)
    assert second_use is False, "reusing an already-consumed nonce must be rejected"
    print("first_use:", first_use, "second_use (reuse):", second_use)


def test_nonce_rejects_wrong_session():
    session_a = uuid.uuid4().hex
    session_b = uuid.uuid4().hex
    _insert_session(session_a)
    _insert_session(session_b)

    resp = client.post("/auth/nonce", json={"session_id": session_a})
    nonce_value = resp.json()["nonce"]

    assert consume_nonce(nonce_value, session_b) is False
    assert consume_nonce(nonce_value, session_a) is True


def test_nonce_rejects_unknown_or_inactive_session():
    resp = client.post("/auth/nonce", json={"session_id": "does-not-exist"})
    assert resp.status_code == 400, resp.text

    inactive_session = uuid.uuid4().hex
    _insert_session(inactive_session, is_active=0)
    resp2 = client.post("/auth/nonce", json={"session_id": inactive_session})
    assert resp2.status_code == 400, resp2.text


def test_nonce_is_issued_with_the_configured_ttl():
    session_id = uuid.uuid4().hex
    _insert_session(session_id)

    nonce_value = client.post("/auth/nonce", json={"session_id": session_id}).json()["nonce"]

    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT issued_at, expires_at FROM nonces WHERE nonce = ?", (nonce_value,)
        ).fetchone()
    finally:
        conn.close()

    issued = datetime.fromisoformat(row["issued_at"])
    expires = datetime.fromisoformat(row["expires_at"])
    assert (expires - issued).total_seconds() == NONCE_TTL_SECONDS


def test_expired_nonce_is_rejected():
    session_id = uuid.uuid4().hex
    _insert_session(session_id)

    nonce_value = client.post("/auth/nonce", json={"session_id": session_id}).json()["nonce"]

    # Age the nonce past its window by driving stored state directly, rather
    # than sleeping against a process-global TTL that another test module
    # may have already fixed at import time.
    expired_at = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
    conn = get_connection()
    try:
        conn.execute("UPDATE nonces SET expires_at = ? WHERE nonce = ?", (expired_at, nonce_value))
        conn.commit()
    finally:
        conn.close()

    assert consume_nonce(nonce_value, session_id) is False, "an expired nonce must be rejected"
