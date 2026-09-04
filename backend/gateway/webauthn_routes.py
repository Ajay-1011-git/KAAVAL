# backend/gateway/webauthn_routes.py
#
# T-RO.2: POST /auth/webauthn/register/begin, /finish
# (T-RO.3 login endpoints are added to this same file in a later task.)
#
# Uses the `webauthn` (py_webauthn) package. Its real current API (v3.0.0)
# was inspected in-session before writing any of the calls below — see the
# ANTI-HALLUCINATION RULES in CLAUDE.md. Do not assume method names or
# return shapes for this library from memory; re-verify if the pinned
# version in backend/requirements.txt ever changes.

import json
import os
import uuid
from datetime import datetime, timezone

import webauthn
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from webauthn.helpers import bytes_to_base64url, options_to_json_dict
from webauthn.helpers.exceptions import InvalidRegistrationResponse
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    PublicKeyCredentialDescriptor,
)

from backend.db import get_connection
from backend.events import write_event
from backend.contracts import SecurityEvent

router = APIRouter()

RP_ID = os.environ.get("WEBAUTHN_RP_ID", "kaaval-demo.local")
RP_ORIGIN = os.environ.get("WEBAUTHN_RP_ORIGIN", "https://kaaval-demo.local")
RP_NAME = "KAAVAL"

# --- Local schema (scoped to this file per T-RO.2/T-RO.3's "files you may
# touch" — deliberately not added to backend/db.py's shared schema). ---
_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    user_id     TEXT PRIMARY KEY,
    username    TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    credential_id                TEXT PRIMARY KEY,  -- base64url
    user_id                      TEXT NOT NULL,
    public_key                   TEXT NOT NULL,      -- base64url CBOR COSE key
    sign_count                   INTEGER NOT NULL,
    registered_session_public_key TEXT,               -- JSON JWK submitted at register/finish
    created_at                   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_id
    ON webauthn_credentials (user_id);

CREATE TABLE IF NOT EXISTS webauthn_challenges (
    username        TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL,
    challenge       TEXT NOT NULL,  -- base64url
    ceremony_type   TEXT NOT NULL,  -- "registration" | "authentication"
    created_at      TEXT NOT NULL
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


def _get_or_create_user(username: str) -> str:
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT user_id FROM users WHERE username = ?", (username,)
        ).fetchone()
        if row:
            return row["user_id"]
        user_id = uuid.uuid4().hex
        conn.execute(
            "INSERT INTO users (user_id, username) VALUES (?, ?)", (user_id, username)
        )
        conn.commit()
        return user_id
    finally:
        conn.close()


def _get_user_credentials(user_id: str) -> list[dict]:
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT credential_id, public_key, sign_count FROM webauthn_credentials WHERE user_id = ?",
            (user_id,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ---------------------------------------------------------------------
# T-RO.2 — registration
# ---------------------------------------------------------------------

class RegisterBeginRequest(BaseModel):
    username: str


@router.post("/auth/webauthn/register/begin")
def register_begin(body: RegisterBeginRequest):
    user_id = _get_or_create_user(body.username)
    existing = _get_user_credentials(user_id)

    options = webauthn.generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_name=body.username,
        user_id=user_id.encode("utf-8"),
        user_display_name=body.username,
        attestation=AttestationConveyancePreference.NONE,
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=webauthn.base64url_to_bytes(c["credential_id"]))
            for c in existing
        ],
    )

    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO webauthn_challenges (username, user_id, challenge, ceremony_type, created_at)
            VALUES (?, ?, ?, 'registration', ?)
            ON CONFLICT(username) DO UPDATE SET
                user_id=excluded.user_id, challenge=excluded.challenge,
                ceremony_type=excluded.ceremony_type, created_at=excluded.created_at
            """,
            (body.username, user_id, bytes_to_base64url(options.challenge), _now()),
        )
        conn.commit()
    finally:
        conn.close()

    return options_to_json_dict(options)


class RegisterFinishRequest(BaseModel):
    username: str
    credential: dict  # RegistrationResponseJSON, as produced by navigator.credentials.create()
    session_public_key: dict  # JWK of the newly generated, non-exportable session key pair


@router.post("/auth/webauthn/register/finish")
def register_finish(body: RegisterFinishRequest):
    conn = get_connection()
    try:
        challenge_row = conn.execute(
            "SELECT user_id, challenge FROM webauthn_challenges WHERE username = ? AND ceremony_type = 'registration'",
            (body.username,),
        ).fetchone()
    finally:
        conn.close()

    if challenge_row is None:
        raise HTTPException(status_code=400, detail="no_pending_registration_challenge")

    expected_challenge = webauthn.base64url_to_bytes(challenge_row["challenge"])

    try:
        verified = webauthn.verify_registration_response(
            credential=body.credential,
            expected_challenge=expected_challenge,
            expected_rp_id=RP_ID,
            expected_origin=RP_ORIGIN,
        )
    except InvalidRegistrationResponse as exc:
        raise HTTPException(status_code=400, detail=f"registration_verification_failed: {exc}")

    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO webauthn_credentials
                (credential_id, user_id, public_key, sign_count, registered_session_public_key, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                bytes_to_base64url(verified.credential_id),
                challenge_row["user_id"],
                bytes_to_base64url(verified.credential_public_key),
                verified.sign_count,
                json.dumps(body.session_public_key),
                _now(),
            ),
        )
        conn.execute("DELETE FROM webauthn_challenges WHERE username = ?", (body.username,))
        conn.commit()
    finally:
        conn.close()

    return {
        "verified": True,
        "credential_id": bytes_to_base64url(verified.credential_id),
        "user_id": challenge_row["user_id"],
    }
