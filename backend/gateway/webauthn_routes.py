# backend/gateway/webauthn_routes.py
#
# T-RO.2: POST /auth/webauthn/register/begin, /finish
# T-RO.3: POST /auth/webauthn/login/begin, /finish
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
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from webauthn.helpers import bytes_to_base64url, options_to_json_dict
from webauthn.helpers.exceptions import InvalidRegistrationResponse, InvalidAuthenticationResponse
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)

from backend.db import get_connection
from backend.events import write_event
from backend.contracts import SecurityEvent

router = APIRouter()

RP_ID = os.environ.get("WEBAUTHN_RP_ID", "kaaval-demo.local")
RP_ORIGIN = os.environ.get("WEBAUTHN_RP_ORIGIN", "https://kaaval-demo.local")
RP_NAME = "KAAVAL"

# The demo application's session cookie. Defined here, where the session is
# actually created, and imported by demo_app_routes.py so there is exactly
# one spelling of the name.
#
# This cookie is DELIBERATELY an ordinary bearer cookie — it is the thing
# PulseLock exists to make insufficient. Baseline mode trusts it (PRD FR-14's
# required negative control); protected mode ignores it entirely and trusts
# only the signature. HttpOnly is set because the threat model here is an
# AiTM proxy capturing it in transit, not script access.
SESSION_COOKIE_NAME = "kaaval_session"

# Secure is derived from the configured RP origin so the local http demo
# actually receives the cookie, and an https deployment still gets the flag.
# Override explicitly with SESSION_COOKIE_SECURE=true|false.
# An empty value counts as unset, so copying .env.example (which ships the
# key blank) still derives rather than silently forcing the flag off.
_secure_override = os.environ.get("SESSION_COOKIE_SECURE", "").strip().lower()
SESSION_COOKIE_SECURE = (
    _secure_override in ("1", "true", "yes", "on")
    if _secure_override
    else RP_ORIGIN.lower().startswith("https://")
)

# A WebAuthn challenge is single-use and short-lived, same reasoning as the
# nonce TTL in nonce.py: a challenge row that never expires is a stale
# ceremony left permanently open. Matches NONCE_TTL_SECONDS by default.
CHALLENGE_TTL_SECONDS = int(os.environ.get("WEBAUTHN_CHALLENGE_TTL_SECONDS", "120"))

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


def _now_dt() -> datetime:
    return datetime.now(timezone.utc)


def _now() -> str:
    return _now_dt().isoformat().replace("+00:00", "Z")


def _challenge_is_fresh(created_at: str) -> bool:
    """Reject a challenge older than CHALLENGE_TTL_SECONDS."""
    try:
        created = datetime.fromisoformat(created_at)
    except ValueError:
        return False
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return (_now_dt() - created).total_seconds() <= CHALLENGE_TTL_SECONDS


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


def _get_user_id_by_username(username: str) -> str | None:
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT user_id FROM users WHERE username = ?", (username,)
        ).fetchone()
        return row["user_id"] if row else None
    finally:
        conn.close()


def _get_credential(credential_id_b64: str) -> dict | None:
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT credential_id, user_id, public_key, sign_count FROM webauthn_credentials WHERE credential_id = ?",
            (credential_id_b64,),
        ).fetchone()
        return dict(row) if row else None
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
            "SELECT user_id, challenge, created_at FROM webauthn_challenges WHERE username = ? AND ceremony_type = 'registration'",
            (body.username,),
        ).fetchone()
    finally:
        conn.close()

    if challenge_row is None:
        raise HTTPException(status_code=400, detail="no_pending_registration_challenge")
    if not _challenge_is_fresh(challenge_row["created_at"]):
        raise HTTPException(status_code=400, detail="registration_challenge_expired")

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


# ---------------------------------------------------------------------
# T-RO.3 — login + session binding
# ---------------------------------------------------------------------

class LoginBeginRequest(BaseModel):
    username: str


@router.post("/auth/webauthn/login/begin")
def login_begin(body: LoginBeginRequest):
    user_id = _get_user_id_by_username(body.username)
    if user_id is None:
        # Same shape as "no credentials" below — don't reveal whether a
        # username exists via a different error.
        raise HTTPException(status_code=400, detail="no_credentials_for_user")

    credentials = _get_user_credentials(user_id)
    if not credentials:
        raise HTTPException(status_code=400, detail="no_credentials_for_user")

    options = webauthn.generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=webauthn.base64url_to_bytes(c["credential_id"]))
            for c in credentials
        ],
        user_verification=UserVerificationRequirement.PREFERRED,
    )

    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO webauthn_challenges (username, user_id, challenge, ceremony_type, created_at)
            VALUES (?, ?, ?, 'authentication', ?)
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


class LoginFinishRequest(BaseModel):
    username: str
    credential: dict  # AuthenticationResponseJSON, as produced by navigator.credentials.get()
    session_public_key: dict  # JWK of the newly generated, non-exportable session key pair to bind


@router.post("/auth/webauthn/login/finish")
def login_finish(body: LoginFinishRequest):
    conn = get_connection()
    try:
        challenge_row = conn.execute(
            "SELECT user_id, challenge, created_at FROM webauthn_challenges WHERE username = ? AND ceremony_type = 'authentication'",
            (body.username,),
        ).fetchone()
    finally:
        conn.close()

    if challenge_row is None:
        raise HTTPException(status_code=400, detail="no_pending_login_challenge")
    if not _challenge_is_fresh(challenge_row["created_at"]):
        raise HTTPException(status_code=400, detail="login_challenge_expired")

    credential_id_b64 = body.credential.get("id")
    stored_credential = _get_credential(credential_id_b64) if credential_id_b64 else None
    if stored_credential is None or stored_credential["user_id"] != challenge_row["user_id"]:
        raise HTTPException(status_code=400, detail="unknown_credential")

    expected_challenge = webauthn.base64url_to_bytes(challenge_row["challenge"])

    try:
        verified = webauthn.verify_authentication_response(
            credential=body.credential,
            expected_challenge=expected_challenge,
            expected_rp_id=RP_ID,
            expected_origin=RP_ORIGIN,
            credential_public_key=webauthn.base64url_to_bytes(stored_credential["public_key"]),
            credential_current_sign_count=stored_credential["sign_count"],
        )
    except InvalidAuthenticationResponse as exc:
        raise HTTPException(status_code=400, detail=f"login_verification_failed: {exc}")

    session_id = uuid.uuid4().hex
    now = _now()

    conn = get_connection()
    try:
        conn.execute(
            "UPDATE webauthn_credentials SET sign_count = ? WHERE credential_id = ?",
            (verified.new_sign_count, credential_id_b64),
        )
        conn.execute(
            """
            INSERT INTO sessions
                (session_id, user_id, public_key_jwk, credential_id, is_active, last_sequence, created_at)
            VALUES (?, ?, ?, ?, 1, 0, ?)
            """,
            (
                session_id,
                challenge_row["user_id"],
                json.dumps(body.session_public_key),
                credential_id_b64,
                now,
            ),
        )
        conn.execute("DELETE FROM webauthn_challenges WHERE username = ?", (body.username,))
        conn.commit()
    finally:
        conn.close()

    write_event(
        SecurityEvent(
            event_id=uuid.uuid4().hex,
            timestamp=now,
            event_type="session_bound",
            session_id=session_id,
            user_id=challenge_row["user_id"],
            application_id=None,
            reason="webauthn_login_success",
            detail={"credential_id": credential_id_b64},
            severity="info",
        )
    )

    # Issue the demo application's session cookie. Without this the browser
    # holds nothing after a successful login, so baseline mode's
    # cookie-only path (demo_app_routes.py) is unreachable from a real
    # browser and PRD FR-14 Scene 1 cannot be demonstrated — only simulated
    # by hand-crafting a Cookie header.
    response = JSONResponse({"session_id": session_id})
    response.set_cookie(
        SESSION_COOKIE_NAME,
        session_id,
        httponly=True,
        samesite="lax",
        secure=SESSION_COOKIE_SECURE,
        path="/",
    )
    return response
