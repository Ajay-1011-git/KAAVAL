# backend/gateway/test_webauthn_routes.py
#
# T-RO.2 VERIFY: integration test simulating a registration ceremony.
# T-RO.3 VERIFY: integration test simulating a login ceremony that binds
# a session and writes a `session_bound` SecurityEvent.
#
# The `webauthn` (py_webauthn) package ships no mock/test attestation
# helpers in its published wheel (verified in-session: `webauthn.helpers`
# exposes only encode/decode/verify primitives, no fixture generator) —
# its own test suite instead uses hardcoded byte fixtures captured from
# real authenticators, which aren't distributed with the package and
# can't be regenerated for an arbitrary rp_id/origin/challenge.
#
# So these tests drive a small, real, self-contained "software
# authenticator": it generates a genuine ECDSA P-256 key pair, builds
# spec-shaped `attestationObject`/`authenticatorData`/`clientDataJSON` by
# hand, and signs with the real private key. Every byte layout below was
# checked against `webauthn.helpers.parse_authenticator_data`'s real
# source in-session before writing this. This exercises the server's real
# verification code path — nothing about the tests' *output* is
# fabricated, only the "browser + authenticator" they stand in for.
#
# DATABASE_URL is pointed at an isolated temp file BEFORE backend.db (or
# anything importing it) is first imported anywhere in this process —
# backend/db.py reads it into a module-level constant at import time, so
# setting it later (e.g. via monkeypatch inside a test function, after a
# previous test already triggered the import) would silently no-op.
# Tests in this file use distinct usernames so they can safely share one
# database file.

import os
import tempfile

_TEST_DB_DIR = tempfile.mkdtemp(prefix="kaaval_test_")
os.environ["DATABASE_URL"] = f"sqlite:///{_TEST_DB_DIR}/test_kaaval.db"

import hashlib  # noqa: E402
import json
from datetime import datetime, timedelta, timezone  # noqa: E402

import cbor2  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url  # noqa: E402

from backend.db import init_db, get_connection  # noqa: E402
from backend.gateway import webauthn_routes  # noqa: E402
from backend.gateway.webauthn_routes import SESSION_COOKIE_NAME  # noqa: E402

from backend.gateway.webauthn_routes import router, RP_ID, RP_ORIGIN  # noqa: E402

init_db()

app = FastAPI()
app.include_router(router)
client = TestClient(app)


class SoftAuthenticator:
    """A minimal, real, self-consistent virtual WebAuthn authenticator for tests."""

    def __init__(self, rp_id: str):
        self.rp_id = rp_id
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(16)
        self.sign_count = 0

    def _rp_id_hash(self) -> bytes:
        return hashlib.sha256(self.rp_id.encode("utf-8")).digest()

    def _cose_public_key(self) -> bytes:
        numbers = self.private_key.public_key().public_numbers()
        x = numbers.x.to_bytes(32, "big")
        y = numbers.y.to_bytes(32, "big")
        # COSE EC2 key: {1: kty=2 (EC2), 3: alg=-7 (ES256), -1: crv=1 (P-256), -2: x, -3: y}
        cose_key = {1: 2, 3: -7, -1: 1, -2: x, -3: y}
        return cbor2.dumps(cose_key)

    def create_attestation(self, challenge: bytes, origin: str) -> dict:
        """Simulate navigator.credentials.create() -> RegistrationResponseJSON."""
        flags = 0x45  # UP (0x01) | UV (0x04) | AT (0x40)
        sign_count_bytes = self.sign_count.to_bytes(4, "big")
        attested_cred_data = (
            b"\x00" * 16  # aaguid
            + len(self.credential_id).to_bytes(2, "big")
            + self.credential_id
            + self._cose_public_key()
        )
        auth_data = self._rp_id_hash() + bytes([flags]) + sign_count_bytes + attested_cred_data

        attestation_object = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})

        client_data = json.dumps(
            {
                "type": "webauthn.create",
                "challenge": bytes_to_base64url(challenge),
                "origin": origin,
                "crossOrigin": False,
            }
        ).encode("utf-8")

        cred_id_b64 = bytes_to_base64url(self.credential_id)
        return {
            "id": cred_id_b64,
            "rawId": cred_id_b64,
            "type": "public-key",
            "response": {
                "clientDataJSON": bytes_to_base64url(client_data),
                "attestationObject": bytes_to_base64url(attestation_object),
            },
        }

    def create_assertion(self, challenge: bytes, origin: str) -> dict:
        """Simulate navigator.credentials.get() -> AuthenticationResponseJSON."""
        self.sign_count += 1
        flags = 0x05  # UP (0x01) | UV (0x04), no attested credential data in an assertion
        sign_count_bytes = self.sign_count.to_bytes(4, "big")
        auth_data = self._rp_id_hash() + bytes([flags]) + sign_count_bytes

        client_data = json.dumps(
            {
                "type": "webauthn.get",
                "challenge": bytes_to_base64url(challenge),
                "origin": origin,
                "crossOrigin": False,
            }
        ).encode("utf-8")

        signed_data = auth_data + hashlib.sha256(client_data).digest()
        signature = self.private_key.sign(signed_data, ec.ECDSA(hashes.SHA256()))

        cred_id_b64 = bytes_to_base64url(self.credential_id)
        return {
            "id": cred_id_b64,
            "rawId": cred_id_b64,
            "type": "public-key",
            "response": {
                "clientDataJSON": bytes_to_base64url(client_data),
                "authenticatorData": bytes_to_base64url(auth_data),
                "signature": bytes_to_base64url(signature),
            },
        }


def _register(username: str) -> SoftAuthenticator:
    begin_resp = client.post("/auth/webauthn/register/begin", json={"username": username})
    assert begin_resp.status_code == 200, begin_resp.text
    options = begin_resp.json()
    assert options["rp"]["id"] == RP_ID

    challenge_bytes = base64url_to_bytes(options["challenge"])
    authenticator = SoftAuthenticator(rp_id=RP_ID)
    credential = authenticator.create_attestation(challenge_bytes, RP_ORIGIN)

    finish_resp = client.post(
        "/auth/webauthn/register/finish",
        json={
            "username": username,
            "credential": credential,
            "session_public_key": {
                "kty": "EC", "crv": "P-256", "x": "reg-x", "y": "reg-y", "key_ops": ["verify"],
            },
        },
    )
    assert finish_resp.status_code == 200, finish_resp.text
    return authenticator


def test_registration_ceremony_persists_credential_and_session_key():
    username = "alice@example.com"
    authenticator = _register(username)

    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM webauthn_credentials WHERE credential_id = ?",
            (bytes_to_base64url(authenticator.credential_id),),
        ).fetchone()
    finally:
        conn.close()

    assert row is not None
    assert json.loads(row["registered_session_public_key"])["x"] == "reg-x"
    print("PERSISTED CREDENTIAL ROW:", dict(row))


def test_login_ceremony_binds_session_and_writes_event():
    username = "bob@example.com"
    authenticator = _register(username)

    login_begin_resp = client.post("/auth/webauthn/login/begin", json={"username": username})
    assert login_begin_resp.status_code == 200, login_begin_resp.text
    login_options = login_begin_resp.json()
    assert login_options["rpId"] == RP_ID

    login_challenge = base64url_to_bytes(login_options["challenge"])
    assertion = authenticator.create_assertion(login_challenge, RP_ORIGIN)

    session_public_key_jwk = {
        "kty": "EC", "crv": "P-256", "x": "login-x", "y": "login-y", "key_ops": ["verify"],
    }

    login_finish_resp = client.post(
        "/auth/webauthn/login/finish",
        json={
            "username": username,
            "credential": assertion,
            "session_public_key": session_public_key_jwk,
        },
    )
    assert login_finish_resp.status_code == 200, login_finish_resp.text
    session_id = login_finish_resp.json()["session_id"]
    assert session_id

    conn = get_connection()
    try:
        session_row = conn.execute(
            "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
        cred_row = conn.execute(
            "SELECT sign_count FROM webauthn_credentials WHERE credential_id = ?",
            (bytes_to_base64url(authenticator.credential_id),),
        ).fetchone()
    finally:
        conn.close()

    assert session_row is not None
    assert session_row["is_active"] == 1
    assert json.loads(session_row["public_key_jwk"]) == session_public_key_jwk
    assert cred_row["sign_count"] == authenticator.sign_count  # updated from verified.new_sign_count
    print("PERSISTED SESSION ROW:", dict(session_row))

    # Queried directly rather than via get_events_since(0): that helper is
    # the SSE stream's cursor read and caps at 100 rows, so it silently
    # misses this event once a full-suite run has written more than 100.
    conn = get_connection()
    try:
        events = conn.execute(
            "SELECT event_type, reason, severity FROM events WHERE session_id = ? ORDER BY rowid",
            (session_id,),
        ).fetchall()
    finally:
        conn.close()

    assert len(events) == 1
    assert events[0]["event_type"] == "session_bound"
    assert events[0]["reason"] == "webauthn_login_success"
    print("SECURITY EVENT:", dict(events[0]))


def test_login_issues_the_demo_session_cookie():
    """Without this cookie, baseline mode is unreachable from a real browser.

    PRD FR-14's negative control depends on the victim's browser genuinely
    holding a session cookie after login — not on a Cookie header being
    hand-crafted by the attacker console.
    """
    username = "carol@example.com"
    authenticator = _register(username)

    login_begin_resp = client.post("/auth/webauthn/login/begin", json={"username": username})
    challenge = base64url_to_bytes(login_begin_resp.json()["challenge"])
    assertion = authenticator.create_assertion(challenge, RP_ORIGIN)

    response = client.post(
        "/auth/webauthn/login/finish",
        json={
            "username": username,
            "credential": assertion,
            "session_public_key": {
                "kty": "EC", "crv": "P-256", "x": "cookie-x", "y": "cookie-y",
            },
        },
    )
    assert response.status_code == 200, response.text
    session_id = response.json()["session_id"]

    set_cookie = response.headers.get("set-cookie", "")
    print("SET-COOKIE:", set_cookie)
    assert f"{SESSION_COOKIE_NAME}={session_id}" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "Path=/" in set_cookie
    # The cookie the client will actually send back on the next request.
    assert client.cookies.get(SESSION_COOKIE_NAME) == session_id


def test_an_expired_challenge_is_rejected():
    """A pending ceremony must not stay open forever."""
    username = "dave@example.com"
    _register(username)

    client.post("/auth/webauthn/login/begin", json={"username": username})

    # Age the stored challenge past its TTL.
    stale = datetime.now(timezone.utc) - timedelta(
        seconds=webauthn_routes.CHALLENGE_TTL_SECONDS + 60
    )
    conn = get_connection()
    try:
        conn.execute(
            "UPDATE webauthn_challenges SET created_at = ? WHERE username = ?",
            (stale.isoformat().replace("+00:00", "Z"), username),
        )
        conn.commit()
    finally:
        conn.close()

    response = client.post(
        "/auth/webauthn/login/finish",
        json={
            "username": username,
            "credential": {"id": "whatever", "type": "public-key", "response": {}},
            "session_public_key": {"kty": "EC", "crv": "P-256", "x": "a", "y": "b"},
        },
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "login_challenge_expired"
    print("EXPIRED CHALLENGE REJECTED:", response.json())
