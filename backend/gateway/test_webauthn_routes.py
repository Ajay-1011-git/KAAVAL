# backend/gateway/test_webauthn_routes.py
#
# T-RO.2 VERIFY: integration test simulating a registration ceremony.
#
# The `webauthn` (py_webauthn) package ships no mock/test attestation
# helpers in its published wheel (verified in-session: `webauthn.helpers`
# exposes only encode/decode/verify primitives, no fixture generator) —
# its own test suite instead uses hardcoded byte fixtures captured from
# real authenticators, which aren't distributed with the package and
# can't be regenerated for an arbitrary rp_id/origin/challenge.
#
# So this test drives a small, real, self-contained "software
# authenticator": it generates a genuine ECDSA P-256 key pair, builds a
# spec-shaped `attestationObject`/`clientDataJSON` by hand, and signs with
# the real private key. Every byte layout below was checked against
# `webauthn.helpers.parse_authenticator_data`'s real source in-session
# before writing this. This exercises the server's real verification code
# path — nothing about the test's *output* is fabricated, only the
# "browser + authenticator" it stands in for.
#
# Note: backend.db / backend.gateway.webauthn_routes are deliberately NOT
# imported at module level — both read DATABASE_URL at import time
# (backend/db.py's module-level constant, and this module's own
# `_ensure_schema()` call), so they must only be imported after the test
# has pointed DATABASE_URL at an isolated file via monkeypatch.

import hashlib
import json

import cbor2
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI
from fastapi.testclient import TestClient


class SoftAuthenticator:
    """A minimal, real, self-consistent virtual WebAuthn authenticator for tests."""

    def __init__(self, rp_id: str):
        self.rp_id = rp_id
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = b"\x01" * 16
        self.sign_count = 0

    def _cose_public_key(self) -> bytes:
        numbers = self.private_key.public_key().public_numbers()
        x = numbers.x.to_bytes(32, "big")
        y = numbers.y.to_bytes(32, "big")
        # COSE EC2 key: {1: kty=2 (EC2), 3: alg=-7 (ES256), -1: crv=1 (P-256), -2: x, -3: y}
        cose_key = {1: 2, 3: -7, -1: 1, -2: x, -3: y}
        return cbor2.dumps(cose_key)

    def create_attestation(self, challenge: bytes, origin: str, bytes_to_base64url) -> dict:
        """Simulate navigator.credentials.create() -> RegistrationResponseJSON."""
        rp_id_hash = hashlib.sha256(self.rp_id.encode("utf-8")).digest()
        flags = 0x45  # UP (0x01) | UV (0x04) | AT (0x40)
        sign_count_bytes = self.sign_count.to_bytes(4, "big")
        attested_cred_data = (
            b"\x00" * 16  # aaguid
            + len(self.credential_id).to_bytes(2, "big")
            + self.credential_id
            + self._cose_public_key()
        )
        auth_data = rp_id_hash + bytes([flags]) + sign_count_bytes + attested_cred_data

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


def test_registration_ceremony_persists_credential_and_session_key(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test_kaaval.db")

    # Imported here, not at module level, so DATABASE_URL is already set
    # when backend/db.py and webauthn_routes.py read it at import time.
    from backend.db import init_db, get_connection
    from backend.gateway.webauthn_routes import router, RP_ID, RP_ORIGIN
    from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

    init_db()

    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)

    username = "alice@example.com"

    begin_resp = client.post("/auth/webauthn/register/begin", json={"username": username})
    assert begin_resp.status_code == 200, begin_resp.text
    options = begin_resp.json()
    assert options["rp"]["id"] == RP_ID

    challenge_bytes = base64url_to_bytes(options["challenge"])
    authenticator = SoftAuthenticator(rp_id=RP_ID)
    credential = authenticator.create_attestation(challenge_bytes, RP_ORIGIN, bytes_to_base64url)

    session_public_key_jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": "test-x",
        "y": "test-y",
        "key_ops": ["verify"],
    }

    finish_resp = client.post(
        "/auth/webauthn/register/finish",
        json={
            "username": username,
            "credential": credential,
            "session_public_key": session_public_key_jwk,
        },
    )
    assert finish_resp.status_code == 200, finish_resp.text
    finish_body = finish_resp.json()
    assert finish_body["verified"] is True

    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM webauthn_credentials WHERE credential_id = ?",
            (finish_body["credential_id"],),
        ).fetchone()
    finally:
        conn.close()

    assert row is not None
    assert row["user_id"] == finish_body["user_id"]
    assert json.loads(row["registered_session_public_key"]) == session_public_key_jwk
    print("PERSISTED ROW:", dict(row))
