# backend/gateway/test_verify.py
#
# T-RO.5 VERIFY: the six required cases from the build document, plus the
# three remaining checks of the seven-step order, plus the PRD §7
# success-metric target (100% rejection rate on the negative cases across
# a repeated run).
#
# The test builds the canonical string INDEPENDENTLY of verify.py (it
# joins the eight fields itself, in the order the TRD fixes) and signs it
# the way Ajay's browser SDK will — Web Crypto's crypto.subtle.sign emits
# a raw IEEE-P1363 (r||s, 64-byte) ECDSA signature, base64'd. If verify.py
# ever reorders a canonical field or mis-handles the signature encoding,
# these tests fail rather than agreeing with the bug.
#
# DATABASE_URL is set before backend.db is first imported in this process
# — see the note in test_webauthn_routes.py for why.

import base64
import hashlib
import json
import os
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

_TEST_DB_DIR = tempfile.mkdtemp(prefix="kaaval_test_verify_")
os.environ["DATABASE_URL"] = f"sqlite:///{_TEST_DB_DIR}/test_kaaval.db"
os.environ["NONCE_TTL_SECONDS"] = "30"
os.environ["REQUEST_FRESHNESS_WINDOW_SECONDS"] = "30"

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from backend.contracts import SignedRequestEnvelope  # noqa: E402
from backend.db import init_db, get_connection  # noqa: E402
from backend.gateway.nonce import router as nonce_router  # noqa: E402
from backend.gateway.verify import ActualRequest, verify_proof, verify_request  # noqa: E402

init_db()

app = FastAPI()
app.include_router(nonce_router)
client = TestClient(app)

ORIGIN = "https://kaaval-demo.local"
PATH = "/api/transfer"
METHOD = "POST"


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class BrowserSessionKey:
    """Stands in for the SDK's non-exportable Web Crypto session key pair."""

    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1())

    def public_jwk(self) -> dict:
        nums = self.private_key.public_key().public_numbers()
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64url_encode(nums.x.to_bytes(32, "big")),
            "y": _b64url_encode(nums.y.to_bytes(32, "big")),
        }

    def sign_base64(self, message: str) -> str:
        """Sign like crypto.subtle.sign: raw IEEE-P1363 (r||s), then base64."""
        der = self.private_key.sign(message.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        r, s = asym_utils.decode_dss_signature(der)
        raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return base64.b64encode(raw).decode()


def _canonical(session_id, method, origin, path, body_hash, nonce, sequence, timestamp) -> str:
    """Built independently of verify.py, in the exact order TRD §6.1 fixes."""
    return "\n".join(
        [session_id, method, origin, path, body_hash, nonce, str(sequence), timestamp]
    )


def _new_session(key: BrowserSessionKey, is_active: int = 1) -> str:
    session_id = uuid.uuid4().hex
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO sessions (session_id, user_id, public_key_jwk, credential_id,
                                  is_active, last_sequence, created_at)
            VALUES (?, 'test-user', ?, NULL, ?, 0, ?)
            """,
            (session_id, json.dumps(key.public_jwk()), is_active, _now_iso()),
        )
        conn.commit()
    finally:
        conn.close()
    return session_id


def _issue_nonce(session_id: str) -> str:
    resp = client.post("/auth/nonce", json={"session_id": session_id})
    assert resp.status_code == 200, resp.text
    return resp.json()["nonce"]


def _signed_envelope(
    key: BrowserSessionKey,
    session_id: str,
    *,
    body: bytes = b'{"amount": 100}',
    method: str = METHOD,
    origin: str = ORIGIN,
    path: str = PATH,
    sequence: int = 1,
    timestamp: str | None = None,
    nonce: str | None = None,
    signing_key: BrowserSessionKey | None = None,
) -> SignedRequestEnvelope:
    nonce = nonce if nonce is not None else _issue_nonce(session_id)
    timestamp = timestamp if timestamp is not None else _now_iso()
    body_hash = hashlib.sha256(body).hexdigest()
    canonical = _canonical(
        session_id, method, origin, path, body_hash, nonce, sequence, timestamp
    )
    signer = signing_key or key
    return SignedRequestEnvelope(
        session_id=session_id,
        method=method,
        origin=origin,
        path=path,
        body_hash=body_hash,
        nonce=nonce,
        sequence=sequence,
        timestamp=timestamp,
        signature=signer.sign_base64(canonical),
    )


def _actual(body: bytes = b'{"amount": 100}', method=METHOD, origin=ORIGIN, path=PATH):
    return ActualRequest(method=method, origin=origin, path=path, body=body)


def _proof_header(envelope: SignedRequestEnvelope) -> str:
    return base64.b64encode(envelope.model_dump_json().encode("utf-8")).decode()


def _events_for(session_id: str):
    """Query events for one session directly.

    Deliberately NOT `get_events_since(0)`: that helper is the SSE
    stream's cursor-paging read and caps at 100 rows, so once a run has
    written more than 100 events the row you're looking for silently
    falls outside the window.
    """
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT event_type, reason, severity FROM events WHERE session_id = ? ORDER BY rowid",
            (session_id,),
        ).fetchall()
    finally:
        conn.close()
    return [SimpleNamespace(**dict(r)) for r in rows]


# --- (a) a valid envelope passes all seven checks ---------------------

def test_valid_envelope_passes_all_seven_checks():
    key = BrowserSessionKey()
    session_id = _new_session(key)
    envelope = _signed_envelope(key, session_id)

    result = verify_request(envelope, _actual())

    assert result.ok is True, result.reason
    assert result.reason is None
    events = _events_for(session_id)
    assert [e.event_type for e in events] == ["request_allowed"]


def test_valid_request_advances_the_session_sequence():
    key = BrowserSessionKey()
    session_id = _new_session(key)

    assert verify_request(_signed_envelope(key, session_id, sequence=1), _actual()).ok is True

    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT last_sequence FROM sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
    finally:
        conn.close()
    assert row["last_sequence"] == 1


# --- (b) a missing header is rejected as proof_absent -----------------

def test_missing_proof_header_is_rejected_as_proof_absent():
    result = verify_proof(None, _actual())

    assert result.ok is False
    assert result.reason == "proof_absent"

    conn = get_connection()
    try:
        count = conn.execute(
            "SELECT COUNT(*) AS n FROM events WHERE event_type = 'proof_absent'"
        ).fetchone()["n"]
    finally:
        conn.close()
    assert count >= 1


def test_malformed_proof_header_is_rejected_not_a_500():
    result = verify_proof("this-is-not-base64-json", _actual())

    assert result.ok is False
    assert result.reason == "proof_absent"


def test_valid_proof_header_round_trips_through_verify_proof():
    key = BrowserSessionKey()
    session_id = _new_session(key)
    envelope = _signed_envelope(key, session_id)

    result = verify_proof(_proof_header(envelope), _actual())

    assert result.ok is True, result.reason


# --- check 1: session inactive ---------------------------------------

def test_inactive_session_is_rejected_as_session_inactive():
    key = BrowserSessionKey()
    session_id = _new_session(key, is_active=0)
    # Nonce issuance refuses inactive sessions, so supply one directly.
    envelope = _signed_envelope(key, session_id, nonce="unused-nonce-value")

    result = verify_request(envelope, _actual())

    assert result.ok is False
    assert result.reason == "session_inactive"
    assert result.failed_check == 1


# --- (f) a signature from an unbound key is rejected ------------------

def test_signature_from_unbound_key_is_rejected_as_signature_invalid():
    key = BrowserSessionKey()
    attacker_key = BrowserSessionKey()  # never bound to this session
    session_id = _new_session(key)
    envelope = _signed_envelope(key, session_id, signing_key=attacker_key)

    result = verify_request(envelope, _actual())

    assert result.ok is False
    assert result.reason == "signature_invalid"
    assert result.failed_check == 2
    assert [e.event_type for e in _events_for(session_id)] == ["signature_invalid"]


# --- check 3: method/origin/path mismatch ----------------------------

def test_asserted_path_not_matching_actual_request_is_rejected():
    key = BrowserSessionKey()
    session_id = _new_session(key)
    envelope = _signed_envelope(key, session_id, path="/api/transfer")

    # Envelope is correctly signed, but the request actually hit another path.
    result = verify_request(envelope, _actual(path="/api/profile"))

    assert result.ok is False
    assert result.reason == "request_mismatch"
    assert result.failed_check == 3


def test_asserted_origin_not_matching_actual_request_is_rejected():
    key = BrowserSessionKey()
    session_id = _new_session(key)
    envelope = _signed_envelope(key, session_id, origin=ORIGIN)

    result = verify_request(envelope, _actual(origin="https://kaaval-demo.evil"))

    assert result.ok is False
    assert result.reason == "request_mismatch"


# --- (c) a tampered body is rejected as body_hash_mismatch ------------

def test_tampered_body_is_rejected_as_body_hash_mismatch():
    key = BrowserSessionKey()
    session_id = _new_session(key)
    envelope = _signed_envelope(key, session_id, body=b'{"amount": 100}')

    # The attacker changed the body in flight; the envelope is otherwise intact.
    result = verify_request(envelope, _actual(body=b'{"amount": 999999}'))

    assert result.ok is False
    assert result.reason == "body_hash_mismatch"
    assert result.failed_check == 4
    assert [e.event_type for e in _events_for(session_id)] == ["request_blocked"]


# --- (d) a replayed (reused) nonce is rejected ------------------------

def test_replayed_request_with_reused_nonce_is_rejected():
    key = BrowserSessionKey()
    session_id = _new_session(key)
    envelope = _signed_envelope(key, session_id, sequence=1)

    first = verify_request(envelope, _actual())
    assert first.ok is True, first.reason

    # Byte-identical replay of a legitimately signed request.
    replay = verify_request(envelope, _actual())

    assert replay.ok is False
    assert replay.reason == "nonce_reused"
    assert replay.failed_check == 5
    assert "replay_attempted" in [e.event_type for e in _events_for(session_id)]


def test_unknown_nonce_is_rejected():
    key = BrowserSessionKey()
    session_id = _new_session(key)
    envelope = _signed_envelope(key, session_id, nonce="never-issued-by-this-server")

    result = verify_request(envelope, _actual())

    assert result.ok is False
    assert result.reason == "nonce_reused"


# --- check 6: sequence ------------------------------------------------

def test_non_increasing_sequence_is_rejected():
    key = BrowserSessionKey()
    session_id = _new_session(key)

    assert verify_request(_signed_envelope(key, session_id, sequence=5), _actual()).ok is True

    # A fresh nonce, correctly signed, but the sequence went backwards.
    result = verify_request(_signed_envelope(key, session_id, sequence=3), _actual())

    assert result.ok is False
    assert result.reason == "sequence_invalid"
    assert result.failed_check == 6


# --- (e) a stale timestamp is rejected --------------------------------

def test_stale_timestamp_is_rejected():
    key = BrowserSessionKey()
    session_id = _new_session(key)
    stale = (
        (datetime.now(timezone.utc) - timedelta(minutes=10))
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )
    envelope = _signed_envelope(key, session_id, timestamp=stale)

    result = verify_request(envelope, _actual())

    assert result.ok is False
    assert result.reason == "timestamp_stale"
    assert result.failed_check == 7


def test_far_future_timestamp_is_rejected():
    key = BrowserSessionKey()
    session_id = _new_session(key)
    future = (
        (datetime.now(timezone.utc) + timedelta(minutes=10))
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )
    envelope = _signed_envelope(key, session_id, timestamp=future)

    result = verify_request(envelope, _actual())

    assert result.ok is False
    assert result.reason == "timestamp_stale"


# --- PRD §7: 100% rejection rate on the negative cases ----------------

def test_negative_cases_are_rejected_100_percent_across_repeated_runs():
    """PRD §7's literal success-metric target for cases (b)-(f)."""
    runs = 20
    rejected = 0
    attempted = 0

    for _ in range(runs):
        key = BrowserSessionKey()
        attacker_key = BrowserSessionKey()
        session_id = _new_session(key)

        # (b) missing proof header
        attempted += 1
        rejected += 0 if verify_proof(None, _actual()).ok else 1

        # (c) tampered body
        attempted += 1
        env_c = _signed_envelope(key, session_id, sequence=1)
        rejected += 0 if verify_request(env_c, _actual(body=b"tampered")).ok else 1

        # (d) replayed nonce
        attempted += 1
        env_d = _signed_envelope(key, session_id, sequence=2)
        assert verify_request(env_d, _actual()).ok is True
        rejected += 0 if verify_request(env_d, _actual()).ok else 1

        # (e) stale timestamp
        attempted += 1
        stale = (
            (datetime.now(timezone.utc) - timedelta(minutes=10))
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
        env_e = _signed_envelope(key, session_id, sequence=3, timestamp=stale)
        rejected += 0 if verify_request(env_e, _actual()).ok else 1

        # (f) signature from an unbound key
        attempted += 1
        env_f = _signed_envelope(key, session_id, sequence=4, signing_key=attacker_key)
        rejected += 0 if verify_request(env_f, _actual()).ok else 1

    rejection_rate = rejected / attempted
    print(f"REJECTION RATE: {rejected}/{attempted} = {rejection_rate:.1%}")
    assert rejection_rate == 1.0


# --- PRD §7 / NFR-4: median verification overhead < 100 ms ------------

def test_median_verification_overhead_under_100ms():
    """PRD §7 / NFR-4 / TNFR-1: median server-side proof verification must
    add < 100 ms on local demo hardware. A characterization test — it
    guards the budget against regressions (e.g. someone adding a network
    call into the verification path)."""
    import statistics
    import time

    key = BrowserSessionKey()
    session_id = _new_session(key)

    durations_ms = []
    for sequence in range(1, 31):
        envelope = _signed_envelope(key, session_id, sequence=sequence)
        started = time.perf_counter()
        result = verify_request(envelope, _actual())
        durations_ms.append((time.perf_counter() - started) * 1000)
        assert result.ok is True, result.reason

    median_ms = statistics.median(durations_ms)
    print(
        f"VERIFICATION OVERHEAD: median={median_ms:.2f}ms "
        f"min={min(durations_ms):.2f}ms max={max(durations_ms):.2f}ms over {len(durations_ms)} requests"
    )
    assert median_ms < 100
