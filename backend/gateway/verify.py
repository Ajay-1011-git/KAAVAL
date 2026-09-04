# backend/gateway/verify.py
#
# T-RO.5: the seven-step verification order from TRD §6.1, exactly, as the
# single function every protected route calls. This is the highest-stakes
# correctness surface in KAAVAL — every PRD acceptance criterion about a
# stolen cookie failing depends on this file being right.
#
# The seven checks run IN ORDER and short-circuit on the first failure;
# the failed check is the logged `reason`, never a generic "invalid
# request" (PRD NFR-2):
#
#   1. session active            -> session_inactive
#   2. signature valid           -> signature_invalid
#   3. method/origin/path match  -> request_mismatch
#   4. body_hash matches         -> body_hash_mismatch
#   5. nonce issued and unused   -> nonce_reused
#   6. sequence strictly greater -> sequence_invalid
#   7. timestamp within window   -> timestamp_stale
#
# CRYPTO INTEROP NOTE (verified empirically in-session, do not "simplify"
# this away): the browser SDK signs with Web Crypto's
# crypto.subtle.sign({name:"ECDSA", hash:"SHA-256"}, ...), which emits a
# RAW IEEE-P1363 signature — r||s, 64 bytes for P-256. Python's
# `cryptography` verify() expects DER. So a 64-byte signature is
# converted to DER via encode_dss_signature before verification. Both
# encodings are accepted so the gateway stays compatible with either
# client; the check itself is not weakened by that, since an invalid
# signature fails in either encoding.

import base64
import binascii
import hashlib
import hmac
import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
from pydantic import ValidationError

from backend.contracts import SecurityEvent, SignedRequestEnvelope
from backend.db import get_connection
from backend.events import write_event
from backend.gateway.nonce import consume_nonce

REQUEST_FRESHNESS_WINDOW_SECONDS = int(
    os.environ.get("REQUEST_FRESHNESS_WINDOW_SECONDS", "30")
)

# Which SecurityEvent.event_type each failure reason is reported as
# (TRD §6.2's fixed vocabulary). Every value here is one of the frozen
# literals in backend/contracts.py.
_EVENT_TYPE_BY_REASON = {
    "proof_absent": "proof_absent",
    "session_inactive": "request_blocked",
    "signature_invalid": "signature_invalid",
    "request_mismatch": "request_blocked",
    "body_hash_mismatch": "request_blocked",
    "nonce_reused": "replay_attempted",
    "sequence_invalid": "request_blocked",
    "timestamp_stale": "request_blocked",
}


@dataclass
class ActualRequest:
    """What the server actually received, independent of what the envelope
    asserts. Checks 3 and 4 compare the two."""

    method: str
    origin: str
    path: str
    body: bytes


@dataclass
class VerifyResult:
    ok: bool
    reason: Optional[str] = None
    failed_check: Optional[int] = None
    event: Optional[SecurityEvent] = None


def build_canonical_string(envelope: SignedRequestEnvelope) -> str:
    """The exact canonical string from TRD §6.1 — fixed order, newline-joined.

    session_id\\nmethod\\norigin\\npath\\nbody_hash\\nnonce\\nsequence\\ntimestamp

    Do not reorder, rename, or add fields: the browser SDK builds this
    same string independently, and any divergence silently breaks every
    signature.
    """
    return "\n".join(
        [
            envelope.session_id,
            envelope.method,
            envelope.origin,
            envelope.path,
            envelope.body_hash,
            envelope.nonce,
            str(envelope.sequence),
            envelope.timestamp,
        ]
    )


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def _b64_decode_any(value: str) -> bytes:
    """Decode standard or URL-safe base64, with or without padding."""
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return base64.urlsafe_b64decode(padded)


def _record(
    reason: str,
    *,
    session_id: Optional[str],
    user_id: Optional[str] = None,
    detail: Optional[dict] = None,
) -> SecurityEvent:
    """Write the rejection event naming the specific failed check."""
    event = SecurityEvent(
        event_id=uuid.uuid4().hex,
        timestamp=_iso(_now()),
        event_type=_EVENT_TYPE_BY_REASON[reason],
        session_id=session_id,
        user_id=user_id,
        application_id=None,
        reason=reason,
        # Small structured values only — never the body, the signature, or
        # any session material (TRD §6.2, PRD NFR-5).
        detail={k: str(v) for k, v in (detail or {}).items()},
        severity="blocked",
    )
    write_event(event)
    return event


def _reject(
    reason: str,
    check: int,
    *,
    session_id: Optional[str],
    user_id: Optional[str] = None,
    detail: Optional[dict] = None,
) -> VerifyResult:
    detail = {**(detail or {}), "failed_check": check}
    event = _record(reason, session_id=session_id, user_id=user_id, detail=detail)
    return VerifyResult(ok=False, reason=reason, failed_check=check, event=event)


def _public_key_from_jwk(jwk: dict) -> ec.EllipticCurvePublicKey:
    """Rebuild the bound ECDSA P-256 public key from the stored JWK.

    Anything unexpected raises — the caller turns that into a
    signature_invalid rejection rather than a 500.
    """
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("bound key is not an EC P-256 key")
    x = int.from_bytes(_b64_decode_any(jwk["x"]), "big")
    y = int.from_bytes(_b64_decode_any(jwk["y"]), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def _signature_to_der(signature_bytes: bytes) -> bytes:
    """Web Crypto emits raw r||s (64 bytes for P-256); `cryptography` wants DER."""
    if len(signature_bytes) == 64:
        r = int.from_bytes(signature_bytes[:32], "big")
        s = int.from_bytes(signature_bytes[32:], "big")
        return asym_utils.encode_dss_signature(r, s)
    return signature_bytes


def _signature_is_valid(envelope: SignedRequestEnvelope, public_key_jwk: str) -> bool:
    try:
        public_key = _public_key_from_jwk(json.loads(public_key_jwk))
        signature = _signature_to_der(_b64_decode_any(envelope.signature))
        canonical = build_canonical_string(envelope).encode("utf-8")
        public_key.verify(signature, canonical, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, KeyError, TypeError, binascii.Error, json.JSONDecodeError):
        # Every failure mode here — wrong key, tampered canonical string,
        # malformed JWK, undecodable signature — is a failed check 2, not
        # a server error.
        return False


def _timestamp_is_fresh(timestamp: str) -> bool:
    try:
        parsed = datetime.fromisoformat(timestamp)
    except ValueError:
        return False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    drift = abs((_now() - parsed).total_seconds())
    return drift <= REQUEST_FRESHNESS_WINDOW_SECONDS


def verify_request(envelope: SignedRequestEnvelope, actual: ActualRequest) -> VerifyResult:
    """Run the seven checks of TRD §6.1 in order, short-circuiting on the
    first failure. Writes a SecurityEvent naming the specific failed check
    on rejection, or `request_allowed` on success."""

    session_id = envelope.session_id

    # --- Check 1: session is active -----------------------------------
    conn = get_connection()
    try:
        session = conn.execute(
            "SELECT user_id, public_key_jwk, is_active, last_sequence FROM sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone()
    finally:
        conn.close()

    if session is None or session["is_active"] != 1:
        return _reject("session_inactive", 1, session_id=session_id)

    user_id = session["user_id"]

    # --- Check 2: signature valid against the key bound to this session ---
    if not _signature_is_valid(envelope, session["public_key_jwk"]):
        return _reject("signature_invalid", 2, session_id=session_id, user_id=user_id)

    # --- Check 3: asserted method/origin/path match what was received ---
    if (
        envelope.method != actual.method
        or envelope.origin != actual.origin
        or envelope.path != actual.path
    ):
        return _reject(
            "request_mismatch",
            3,
            session_id=session_id,
            user_id=user_id,
            detail={
                "asserted_method": envelope.method,
                "actual_method": actual.method,
                "asserted_path": envelope.path,
                "actual_path": actual.path,
                "asserted_origin": envelope.origin,
                "actual_origin": actual.origin,
            },
        )

    # --- Check 4: asserted body_hash matches SHA-256 of the real body ---
    actual_body_hash = hashlib.sha256(actual.body).hexdigest()
    if not hmac.compare_digest(envelope.body_hash.lower(), actual_body_hash):
        return _reject(
            "body_hash_mismatch",
            4,
            session_id=session_id,
            user_id=user_id,
            detail={"asserted_body_hash": envelope.body_hash, "actual_body_hash": actual_body_hash},
        )

    # --- Check 5: nonce was issued by this server and is unused ---------
    # consume_nonce marks the nonce used at this point; it is never
    # reusable afterwards even if check 6 or 7 below rejects the request.
    if not consume_nonce(envelope.nonce, session_id):
        return _reject("nonce_reused", 5, session_id=session_id, user_id=user_id)

    # --- Check 6: sequence strictly greater than the last accepted ------
    if envelope.sequence <= session["last_sequence"]:
        return _reject(
            "sequence_invalid",
            6,
            session_id=session_id,
            user_id=user_id,
            detail={
                "asserted_sequence": envelope.sequence,
                "last_accepted_sequence": session["last_sequence"],
            },
        )

    # --- Check 7: timestamp within the freshness window -----------------
    if not _timestamp_is_fresh(envelope.timestamp):
        return _reject(
            "timestamp_stale",
            7,
            session_id=session_id,
            user_id=user_id,
            detail={
                "asserted_timestamp": envelope.timestamp,
                "window_seconds": REQUEST_FRESHNESS_WINDOW_SECONDS,
            },
        )

    # --- All seven passed: advance the sequence, log the allow ----------
    conn = get_connection()
    try:
        conn.execute(
            "UPDATE sessions SET last_sequence = ? WHERE session_id = ?",
            (envelope.sequence, session_id),
        )
        conn.commit()
    finally:
        conn.close()

    event = SecurityEvent(
        event_id=uuid.uuid4().hex,
        timestamp=_iso(_now()),
        event_type="request_allowed",
        session_id=session_id,
        user_id=user_id,
        application_id=None,
        reason="all_checks_passed",
        detail={"method": envelope.method, "path": envelope.path, "sequence": str(envelope.sequence)},
        severity="info",
    )
    write_event(event)
    return VerifyResult(ok=True, event=event)


def verify_proof(header_value: Optional[str], actual: ActualRequest) -> VerifyResult:
    """Entry point for protected routes: parse the X-KAAVAL-Proof header,
    then run the seven checks.

    A missing header, or one that isn't decodable into a well-formed
    SignedRequestEnvelope, is a rejection — never a 500 (TNFR-2). Both are
    reported as `proof_absent`; the event's detail distinguishes a
    malformed header from a genuinely absent one.
    """
    if not header_value:
        event = _record("proof_absent", session_id=None, detail={"malformed": "false"})
        return VerifyResult(ok=False, reason="proof_absent", event=event)

    try:
        decoded = _b64_decode_any(header_value)
        envelope = SignedRequestEnvelope(**json.loads(decoded))
    except (ValidationError, ValueError, TypeError, binascii.Error, json.JSONDecodeError, UnicodeDecodeError):
        event = _record("proof_absent", session_id=None, detail={"malformed": "true"})
        return VerifyResult(ok=False, reason="proof_absent", event=event)

    return verify_request(envelope, actual)
