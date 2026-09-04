# backend/gateway/test_demo_app_routes.py
#
# T-RO.6 VERIFY: the same request succeeds in baseline mode with only a
# cookie, and is rejected in protected mode without a valid envelope.
#
# This is the pair that makes PRD acceptance criteria 1 and 2
# demonstrable rather than asserted: baseline mode is a REQUIRED negative
# control (a captured cookie really does work), protected mode is the fix.
#
# The envelope-signing helpers here are deliberately a local copy rather
# than an import from test_verify.py: importing another test module would
# execute its module-level temp-DB/env setup and fight with this one's.
#
# DATABASE_URL is set before backend.db is first imported in this process
# — see the note in test_webauthn_routes.py. NOTE also that no test module
# should set a process-global config env var (e.g. NONCE_TTL_SECONDS)
# that another module reads at import time; that makes the suite
# order-dependent.

import base64
import hashlib
import json
import os
import tempfile
import uuid
from datetime import datetime, timezone

_TEST_DB_DIR = tempfile.mkdtemp(prefix="kaaval_test_demo_")
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_TEST_DB_DIR}/test_kaaval.db")

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from backend.db import init_db, get_connection  # noqa: E402
from backend.gateway.demo_app_routes import router as demo_router  # noqa: E402
from backend.gateway.nonce import router as nonce_router  # noqa: E402

init_db()

app = FastAPI()
app.include_router(nonce_router)
app.include_router(demo_router)
client = TestClient(app)

ORIGIN = "https://kaaval-demo.local"
TRANSFER_PATH = "/api/transfer"


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class BrowserSessionKey:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1())

    def public_jwk(self) -> dict:
        n = self.private_key.public_key().public_numbers()
        return {
            "kty": "EC", "crv": "P-256",
            "x": _b64url(n.x.to_bytes(32, "big")),
            "y": _b64url(n.y.to_bytes(32, "big")),
        }

    def sign_base64(self, message: str) -> str:
        der = self.private_key.sign(message.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        r, s = asym_utils.decode_dss_signature(der)
        return base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode()


def _new_session(key: BrowserSessionKey) -> str:
    session_id = uuid.uuid4().hex
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO sessions (session_id, user_id, public_key_jwk, credential_id,
                                  is_active, last_sequence, created_at)
            VALUES (?, 'demo-user', ?, NULL, 1, 0, ?)
            """,
            (session_id, json.dumps(key.public_jwk()), _now_iso()),
        )
        conn.commit()
    finally:
        conn.close()
    return session_id


def _proof_header(key: BrowserSessionKey, session_id: str, body: bytes, sequence: int) -> str:
    nonce = client.post("/auth/nonce", json={"session_id": session_id}).json()["nonce"]
    timestamp = _now_iso()
    body_hash = hashlib.sha256(body).hexdigest()
    canonical = "\n".join(
        [session_id, "POST", ORIGIN, TRANSFER_PATH, body_hash, nonce, str(sequence), timestamp]
    )
    envelope = {
        "session_id": session_id, "method": "POST", "origin": ORIGIN, "path": TRANSFER_PATH,
        "body_hash": body_hash, "nonce": nonce, "sequence": sequence,
        "timestamp": timestamp, "signature": key.sign_base64(canonical),
    }
    return base64.b64encode(json.dumps(envelope).encode("utf-8")).decode()


def _transfer(body: bytes, *, mode: str, cookies=None, proof: str | None = None):
    headers = {"Content-Type": "application/json", "Origin": ORIGIN}
    if proof is not None:
        headers["X-KAAVAL-Proof"] = proof

    # Cookies are set on the client instance, not per-request: httpx
    # deprecates per-request cookies because the persistence behaviour is
    # ambiguous. Cleared first so a test that sends no cookie really
    # sends none.
    client.cookies.clear()
    if cookies:
        client.cookies.update(cookies)

    return client.post(f"{TRANSFER_PATH}?mode={mode}", content=body, headers=headers)


BODY = json.dumps({"to_account": "acct-attacker", "amount": 500}).encode("utf-8")


# --- The T-RO.6 VERIFY pair -------------------------------------------

def test_baseline_mode_accepts_a_plain_cookie_with_no_proof():
    """Required negative control (PRD FR-14): the vulnerability is real."""
    key = BrowserSessionKey()
    session_id = _new_session(key)

    resp = _transfer(BODY, mode="baseline", cookies={"kaaval_session": session_id})

    assert resp.status_code == 200, resp.text
    assert resp.json()["mode"] == "baseline"
    print("BASELINE (cookie only):", resp.status_code, resp.json())


def test_protected_mode_rejects_the_same_request_without_an_envelope():
    """The identical action, same cookie, no proof — now refused."""
    key = BrowserSessionKey()
    session_id = _new_session(key)

    resp = _transfer(BODY, mode="protected", cookies={"kaaval_session": session_id})

    assert resp.status_code == 401, resp.text
    assert resp.json()["detail"]["reason"] == "proof_absent"
    print("PROTECTED (cookie only):", resp.status_code, resp.json())


# --- Protected mode, positive path ------------------------------------

def test_protected_mode_accepts_a_valid_signed_envelope():
    key = BrowserSessionKey()
    session_id = _new_session(key)
    proof = _proof_header(key, session_id, BODY, sequence=1)

    resp = _transfer(BODY, mode="protected", proof=proof)

    assert resp.status_code == 200, resp.text
    assert resp.json()["mode"] == "protected"
    print("PROTECTED (valid envelope):", resp.status_code, resp.json())


def test_protected_mode_rejects_a_replayed_envelope():
    key = BrowserSessionKey()
    session_id = _new_session(key)
    proof = _proof_header(key, session_id, BODY, sequence=1)

    first = _transfer(BODY, mode="protected", proof=proof)
    assert first.status_code == 200, first.text

    replay = _transfer(BODY, mode="protected", proof=proof)

    assert replay.status_code == 401
    assert replay.json()["detail"]["reason"] == "nonce_reused"


def test_protected_mode_rejects_a_body_tampered_in_flight():
    key = BrowserSessionKey()
    session_id = _new_session(key)
    proof = _proof_header(key, session_id, BODY, sequence=1)

    tampered = json.dumps({"to_account": "acct-attacker", "amount": 999999}).encode("utf-8")
    resp = _transfer(tampered, mode="protected", proof=proof)

    assert resp.status_code == 401
    assert resp.json()["detail"]["reason"] == "body_hash_mismatch"


# --- Baseline mode is genuinely replayable (the "before" of the demo) ---

def test_baseline_mode_lets_a_captured_cookie_be_replayed_repeatedly():
    key = BrowserSessionKey()
    session_id = _new_session(key)
    stolen_cookie = {"kaaval_session": session_id}

    results = [
        _transfer(BODY, mode="baseline", cookies=stolen_cookie).status_code for _ in range(3)
    ]

    assert results == [200, 200, 200], "baseline replay must succeed — this is the vulnerability"
    print("BASELINE replay attempts:", results)


def test_baseline_mode_still_requires_some_session_cookie():
    resp = _transfer(BODY, mode="baseline")

    assert resp.status_code == 401
    assert resp.json()["detail"]["reason"] == "no_session_cookie"


# --- The same action really happens in both modes ----------------------

def test_the_same_underlying_action_runs_in_both_modes():
    """The mode toggle must select how the request is authorised, not
    swap in a different action — otherwise the demo compares two
    different things."""
    key = BrowserSessionKey()
    session_id = _new_session(key)

    baseline = _transfer(BODY, mode="baseline", cookies={"kaaval_session": session_id})
    protected = _transfer(
        BODY, mode="protected", proof=_proof_header(key, session_id, BODY, sequence=1)
    )

    assert baseline.status_code == protected.status_code == 200
    assert baseline.json()["amount"] == protected.json()["amount"] == 500
    assert baseline.json()["to_account"] == protected.json()["to_account"] == "acct-attacker"

    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT mode FROM demo_transfers WHERE session_id = ? ORDER BY rowid", (session_id,)
        ).fetchall()
    finally:
        conn.close()
    assert [r["mode"] for r in rows] == ["baseline", "protected"]


def test_baseline_allow_is_recorded_against_the_session_as_a_warning():
    key = BrowserSessionKey()
    session_id = _new_session(key)

    _transfer(BODY, mode="baseline", cookies={"kaaval_session": session_id})

    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT event_type, reason, severity FROM events WHERE session_id = ? ORDER BY rowid",
            (session_id,),
        ).fetchall()
    finally:
        conn.close()

    assert [r["event_type"] for r in rows] == ["request_allowed"]
    assert rows[0]["reason"] == "baseline_mode_no_proof_required"
    assert rows[0]["severity"] == "warning", (
        "an allow that happened only because protection was off is not routine info"
    )
    print("BASELINE EVENT:", dict(rows[0]))


def test_protected_block_is_recorded_without_trusting_the_claimed_session():
    """A blocked no-proof request is logged, but NOT stamped with the
    session_id from the unverified cookie.

    If it were, an attacker could choose whose session appears under
    attack on the dashboard just by setting a cookie — an unverified
    bearer value deciding what the security record says is exactly the
    thing this system exists to reject (PRD NFR-1).
    """
    key = BrowserSessionKey()
    session_id = _new_session(key)

    before = _count_events("proof_absent")
    _transfer(BODY, mode="protected", cookies={"kaaval_session": session_id})
    after = _count_events("proof_absent")

    assert after == before + 1, "the protected block must be visible on the timeline"

    conn = get_connection()
    try:
        stamped = conn.execute(
            "SELECT COUNT(*) AS n FROM events WHERE event_type = 'proof_absent' AND session_id = ?",
            (session_id,),
        ).fetchone()["n"]
        latest = conn.execute(
            "SELECT event_type, session_id, reason, severity FROM events "
            "WHERE event_type = 'proof_absent' ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
    finally:
        conn.close()

    assert stamped == 0
    assert latest["session_id"] is None
    assert latest["severity"] == "blocked"
    print("PROTECTED BLOCK EVENT:", dict(latest))


def _count_events(event_type: str) -> int:
    conn = get_connection()
    try:
        return conn.execute(
            "SELECT COUNT(*) AS n FROM events WHERE event_type = ?", (event_type,)
        ).fetchone()["n"]
    finally:
        conn.close()
