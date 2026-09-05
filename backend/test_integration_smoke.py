# backend/test_integration_smoke.py
#
# Cross-module integration smoke test. Team Integration Plan §4 gates every
# merge on "a smoke test that `main` still boots after the merge"; this is
# that gate, made reproducible.
#
# Unlike each module's own tests, this one deliberately spans all four
# modules at once, exercising the seams that no single branch could test:
#
#   - Ajay's SDK signing format  -> Rohith's verify.py (the canonical string,
#     the raw r||s signature encoding, and the base64 X-KAAVAL-Proof header
#     are reproduced here exactly as sdk/src/canonical.ts + client.ts emit
#     them, so a divergence on either side fails this test)
#   - Rohith's gateway + Adhi's Guardian -> the one shared events table
#   - Adhi's Radar report shape  -> the frozen contracts
#   - Sai's Chronicle            -> real SecurityEvent rows written by the
#     other two modules, not fixtures
#
# It reproduces PRD FR-14's before/after demo: the captured cookie really
# works in baseline mode, and the identical replayed request is rejected in
# protected mode with the specific failed check named.

import base64
import hashlib
import json
import os
import tempfile
import uuid
from datetime import datetime, timezone

_TEST_DB_DIR = tempfile.mkdtemp(prefix="kaaval_test_integration_")
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_TEST_DB_DIR}/test_kaaval.db")
os.environ["CHRONICLE_FALLBACK_MODE"] = "true"

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from backend.db import get_connection, init_db  # noqa: E402
from backend.main import app  # noqa: E402

init_db()
client = TestClient(app)

ORIGIN = "http://testserver"
PATH = "/api/transfer"

# Unique per run so this module composes with the other test modules, which
# share whichever DATABASE_URL was set first (backend/db.py resolves the path
# at import time).
_SUFFIX = uuid.uuid4().hex[:8]
SESSION_ID = f"sess-integration-{_SUFFIX}"
USER_ID = f"user-integration-{_SUFFIX}"
APP_ID = f"app-integration-{_SUFFIX}"

_private_key = ec.generate_private_key(ec.SECP256R1())


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _bind_session() -> None:
    """Bind a session to the public key, as T-RO.3's login ceremony does."""
    numbers = _private_key.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(numbers.x.to_bytes(32, "big")),
        "y": _b64url(numbers.y.to_bytes(32, "big")),
    }
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT OR REPLACE INTO sessions
                (session_id, user_id, public_key_jwk, credential_id,
                 is_active, last_sequence, created_at)
            VALUES (?, ?, ?, ?, 1, 0, ?)
            """,
            (
                SESSION_ID,
                USER_ID,
                json.dumps(jwk),
                f"cred-{_SUFFIX}",
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _sign(canonical: str) -> str:
    """Web Crypto emits raw r||s; `cryptography` signs DER, so convert."""
    der = _private_key.sign(canonical.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    r, s = asym_utils.decode_dss_signature(der)
    return base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode()


def _build_proof(body: bytes, sequence: int) -> str:
    """Exactly what sdk/src/client.ts sends as X-KAAVAL-Proof."""
    nonce = client.post("/auth/nonce", json={"session_id": SESSION_ID}).json()["nonce"]
    envelope = {
        "session_id": SESSION_ID,
        "method": "POST",
        "origin": ORIGIN,
        "path": PATH,
        "body_hash": hashlib.sha256(body).hexdigest(),
        "nonce": nonce,
        "sequence": sequence,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    canonical = "\n".join(
        [
            envelope["session_id"],
            envelope["method"],
            envelope["origin"],
            envelope["path"],
            envelope["body_hash"],
            envelope["nonce"],
            str(envelope["sequence"]),
            envelope["timestamp"],
        ]
    )
    envelope["signature"] = _sign(canonical)
    return base64.b64encode(json.dumps(envelope).encode("utf-8")).decode()


def _headers(proof: str) -> dict:
    return {"X-KAAVAL-Proof": proof, "Origin": ORIGIN, "Content-Type": "application/json"}


BODY = json.dumps({"to_account": "attacker-99", "amount": 5000}).encode()


def test_signed_request_is_accepted_and_its_replay_is_blocked():
    """PRD FR-14 Scene 3: the same envelope twice — accepted, then blocked."""
    _bind_session()
    proof = _build_proof(BODY, sequence=1)

    first = client.post("/api/transfer?mode=protected", content=BODY, headers=_headers(proof))
    assert first.status_code == 200, first.text
    assert first.json()["mode"] == "protected"

    replay = client.post("/api/transfer?mode=protected", content=BODY, headers=_headers(proof))
    assert replay.status_code == 401
    # The specific failed check, never a generic "invalid request" (PRD NFR-2).
    assert replay.json()["detail"]["reason"] == "nonce_reused"
    assert replay.json()["detail"]["failed_check"] == 5


def test_baseline_mode_accepts_the_captured_cookie():
    """PRD FR-14 Scene 2: the negative control must genuinely succeed."""
    _bind_session()
    response = client.post(
        "/api/transfer?mode=baseline",
        content=BODY,
        headers={"Origin": ORIGIN, "Content-Type": "application/json"},
        cookies={"kaaval_session": SESSION_ID},
    )
    assert response.status_code == 200
    assert response.json()["mode"] == "baseline"


def test_protected_mode_rejects_a_request_with_no_proof():
    _bind_session()
    response = client.post(
        "/api/transfer?mode=protected",
        content=BODY,
        headers={"Origin": ORIGIN, "Content-Type": "application/json"},
        cookies={"kaaval_session": SESSION_ID},
    )
    assert response.status_code == 401
    assert response.json()["detail"]["reason"] == "proof_absent"


def test_tampered_body_fails_the_body_hash_check():
    _bind_session()
    proof = _build_proof(BODY, sequence=2)
    tampered = json.dumps({"to_account": "attacker-99", "amount": 999_999}).encode()

    response = client.post(
        "/api/transfer?mode=protected", content=tampered, headers=_headers(proof)
    )
    assert response.status_code == 401
    assert response.json()["detail"]["reason"] == "body_hash_mismatch"
    assert response.json()["detail"]["failed_check"] == 4


def test_revoked_session_fails_check_1_even_with_a_valid_signature():
    """POST /auth/session/revoke flips is_active to 0. Check 1 runs before
    the signature (2), origin/path (3), body_hash (4), nonce (5) or sequence
    (6) — so a request that would otherwise pass every later check must
    still be rejected, and rejected specifically as session_inactive."""
    _bind_session()
    proof = _build_proof(BODY, sequence=100)

    revoke = client.post("/auth/session/revoke", cookies={"kaaval_session": SESSION_ID})
    assert revoke.status_code == 200, revoke.text
    assert revoke.json()["revoked"] is True

    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT is_active FROM sessions WHERE session_id = ?", (SESSION_ID,)
        ).fetchone()
    finally:
        conn.close()
    assert row["is_active"] == 0

    replay = client.post("/api/transfer?mode=protected", content=BODY, headers=_headers(proof))
    assert replay.status_code == 401
    assert replay.json()["detail"]["reason"] == "session_inactive"
    assert replay.json()["detail"]["failed_check"] == 1


def test_forged_signature_with_a_different_key_fails_check_2():
    """Every other field is genuine — a real, unused nonce; the real
    origin/path; a body_hash that matches the body actually sent; a fresh
    timestamp — but the signature is produced by a key that was never bound
    to this session. Isolates check 2 from every other check."""
    _bind_session()
    body = json.dumps({"to_account": "attacker-forged", "amount": 7777}).encode()
    nonce = client.post("/auth/nonce", json={"session_id": SESSION_ID}).json()["nonce"]
    envelope = {
        "session_id": SESSION_ID,
        "method": "POST",
        "origin": ORIGIN,
        "path": PATH,
        "body_hash": hashlib.sha256(body).hexdigest(),
        "nonce": nonce,
        "sequence": 200,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    canonical = "\n".join(
        [
            envelope["session_id"],
            envelope["method"],
            envelope["origin"],
            envelope["path"],
            envelope["body_hash"],
            envelope["nonce"],
            str(envelope["sequence"]),
            envelope["timestamp"],
        ]
    )
    attacker_key = ec.generate_private_key(ec.SECP256R1())  # NOT the key bound to SESSION_ID
    der = attacker_key.sign(canonical.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    r, s = asym_utils.decode_dss_signature(der)
    envelope["signature"] = base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode()
    proof = base64.b64encode(json.dumps(envelope).encode("utf-8")).decode()

    response = client.post("/api/transfer?mode=protected", content=body, headers=_headers(proof))
    assert response.status_code == 401
    assert response.json()["detail"]["reason"] == "signature_invalid"
    assert response.json()["detail"]["failed_check"] == 2


def test_origin_mismatch_fails_check_3_with_an_otherwise_valid_signed_request():
    """The envelope's signature covers its OWN asserted origin, so tampering
    the actual Origin header the request arrives with — while leaving the
    genuinely-signed proof completely untouched — cannot break the
    signature. It fails one check later, at 3."""
    _bind_session()
    proof = _build_proof(BODY, sequence=300)
    spoofed_headers = dict(_headers(proof))
    spoofed_headers["Origin"] = "https://attacker-controlled.demo"

    response = client.post("/api/transfer?mode=protected", content=BODY, headers=spoofed_headers)
    assert response.status_code == 401
    assert response.json()["detail"]["reason"] == "request_mismatch"
    assert response.json()["detail"]["failed_check"] == 3


def test_guardian_and_radar_share_the_gateway_contracts():
    """Guardian writes to the same event bus; Radar matches the frozen shape."""
    oauth = client.post(
        "/guardian/oauth/evaluate",
        json={
            "application_id": APP_ID,
            "application_name": "Totally Safe Reader",
            "publisher_verified": False,
            "requested_scopes": ["Mail.ReadWrite", "offline_access"],
            "redirect_uri": "https://evil.example/cb",
            "offline_access_requested": True,
            "is_org_allowlisted": False,
        },
    )
    assert oauth.status_code == 200
    assert oauth.json()["decision"] == "block"

    device = client.post(
        "/guardian/device-code/evaluate",
        json={
            "application_id": APP_ID,
            "device_registered": False,
            "code_ttl_seconds": 900,
            "is_allowlisted": False,
            "is_sensitive_resource": True,
            "admin_approved": False,
        },
    )
    assert device.status_code == 200
    assert device.json()["decision"] == "block"

    report = client.get("/radar/report?org_id=mock-org-01")
    assert report.status_code == 200
    payload = report.json()
    assert payload["organization_id"] == "mock-org-01"
    assert 0 <= payload["exposure_score"] <= 100
    assert payload["exposure_label"] in {"Low", "Medium", "High"}
    assert payload["findings"]


def test_dashboard_can_read_the_backend_cross_origin():
    """The dashboard is a different origin; without CORS every panel is empty."""
    response = client.get(
        "/radar/report?org_id=mock-org-01",
        headers={"Origin": "http://localhost:3000"},
    )
    assert response.headers.get("access-control-allow-origin") == "http://localhost:3000"


def test_chronicle_explains_real_events_written_by_other_modules():
    """Chronicle reads the shared events table, not a fixture."""
    _bind_session()
    proof = _build_proof(BODY, sequence=3)
    client.post("/api/transfer?mode=protected", content=BODY, headers=_headers(proof))
    client.post("/api/transfer?mode=protected", content=BODY, headers=_headers(proof))

    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT event_id FROM events WHERE session_id = ? ORDER BY rowid",
            (SESSION_ID,),
        ).fetchall()
    finally:
        conn.close()
    event_ids = [row["event_id"] for row in rows][:4]
    assert event_ids, "the gateway should have written events for this session"

    response = client.post("/chronicle/explain", json={"event_ids": event_ids})
    assert response.status_code == 200
    assert response.headers.get("X-KAAVAL-Chronicle-Mode") == "fallback"

    explanation = response.json()
    # Grounding: every referenced id is a real event, in the requested order.
    assert explanation["related_event_ids"] == event_ids
    assert explanation["summary"].strip()


def test_the_events_stream_frames_carry_the_named_security_event_type():
    """The dashboard listens for `event: security_event`; keep them in sync.

    frontend/lib/eventsClient.ts registers a `security_event` listener because
    EventSource.onmessage fires only for unnamed frames. If this frame name
    ever changes, the live feed silently goes empty — so it is asserted here.
    """
    from backend.contracts import SecurityEvent
    from backend.gateway.events_stream import event_to_frame

    event = SecurityEvent(
        event_id=uuid.uuid4().hex,
        timestamp="2026-09-04T16:05:00Z",
        event_type="session_bound",
        session_id=SESSION_ID,
        user_id=USER_ID,
        application_id=None,
        reason="session_key_bound",
        detail={"mode": "pulselock"},
        severity="info",
    )
    frame = event_to_frame(event)
    assert frame["event"] == "security_event"
    assert frame["id"] == event.event_id
    assert json.loads(frame["data"])["event_id"] == event.event_id
