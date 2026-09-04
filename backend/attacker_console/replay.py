#!/usr/bin/env python3
"""
=============================================================================
 KAAVAL ATTACKER CONSOLE  —  SIMULATED ATTACK TOOL, DEMO USE ONLY
=============================================================================

T-RO.8. Stands in for the adversary in an AiTM (Adversary-in-the-Middle)
reverse-proxy phishing attack: the victim really logs in, the attacker
captures the resulting session cookie as it passes through, and replays it
from a "different browser".

It runs the same theft against both modes of the demo app:

  baseline  — the replay SUCCEEDS. That is a REQUIRED negative control
              (PRD FR-14, acceptance criterion 1), not a bug. If this ever
              starts failing, the demo has stopped proving anything.
  protected — the replay FAILS with a specific, logged reason
              (acceptance criterion 2).

It then goes further, because "the cookie alone is useless" is only half
the claim. It also captures a genuine, correctly-signed request from the
victim and (a) replays it verbatim and (b) tampers with its body —
acceptance criteria 4 and 3 respectively.

WHAT THE ATTACKER GETS: the session cookie, and any signed request it saw
on the wire. WHAT IT CANNOT GET: the victim's session private key. That
key is generated non-exportable inside the browser's own security
boundary, so there is nothing for a proxy to intercept. That asymmetry is
the whole point of PulseLock, and this tool is built to make it visible
rather than merely asserted.

Usage:
    python -m backend.attacker_console.replay [--base-url http://127.0.0.1:8000]

Exits non-zero if any scene did not produce its expected outcome, so it
doubles as a pre-demo smoke check.
"""

import argparse
import base64
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils

RP_ID = os.environ.get("WEBAUTHN_RP_ID", "kaaval-demo.local")
RP_ORIGIN = os.environ.get("WEBAUTHN_RP_ORIGIN", "https://kaaval-demo.local")
TRANSFER_PATH = "/api/transfer"


# --- tiny HTTP helper (stdlib only: this is a standalone demo tool) ----

def _request(method, url, *, body=None, headers=None):
    headers = dict(headers or {})
    headers.setdefault("Origin", RP_ORIGIN)
    if body is not None:
        headers.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as response:
            return response.status, json.loads(response.read() or b"null")
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw or b"null")
        except json.JSONDecodeError:
            return exc.code, {"raw": raw.decode(errors="replace")}


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


# --- the victim's browser ---------------------------------------------

class VictimBrowser:
    """Simulates the genuine user's browser: a passkey authenticator plus a
    non-exportable per-session signing key.

    The session private key never leaves this object, exactly as the real
    one never leaves the browser — which is why the attacker below can
    steal the cookie but not the ability to sign.
    """

    def __init__(self, base_url: str, username: str):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.passkey = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(16)
        self.sign_count = 0
        self.session_key = ec.generate_private_key(ec.SECP256R1())  # never exported
        self.session_id = None
        self.sequence = 0

    # -- WebAuthn authenticator internals --

    def _cose_public_key(self) -> bytes:
        n = self.passkey.public_key().public_numbers()
        return cbor2.dumps(
            {1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")}
        )

    def _client_data(self, ceremony: str, challenge: bytes) -> bytes:
        return json.dumps(
            {
                "type": ceremony,
                "challenge": _b64url(challenge),
                "origin": RP_ORIGIN,
                "crossOrigin": False,
            }
        ).encode("utf-8")

    def session_public_jwk(self) -> dict:
        n = self.session_key.public_key().public_numbers()
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64url(n.x.to_bytes(32, "big")),
            "y": _b64url(n.y.to_bytes(32, "big")),
        }

    # -- ceremonies --

    def register(self) -> None:
        status, options = _request(
            "POST",
            f"{self.base_url}/auth/webauthn/register/begin",
            body=json.dumps({"username": self.username}).encode(),
        )
        assert status == 200, f"register/begin failed: {status} {options}"

        challenge = _b64url_decode(options["challenge"])
        auth_data = (
            hashlib.sha256(RP_ID.encode()).digest()
            + bytes([0x45])  # UP | UV | AT
            + self.sign_count.to_bytes(4, "big")
            + b"\x00" * 16
            + len(self.credential_id).to_bytes(2, "big")
            + self.credential_id
            + self._cose_public_key()
        )
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        client_data = self._client_data("webauthn.create", challenge)
        cred_id = _b64url(self.credential_id)

        status, body = _request(
            "POST",
            f"{self.base_url}/auth/webauthn/register/finish",
            body=json.dumps(
                {
                    "username": self.username,
                    "credential": {
                        "id": cred_id,
                        "rawId": cred_id,
                        "type": "public-key",
                        "response": {
                            "clientDataJSON": _b64url(client_data),
                            "attestationObject": _b64url(attestation),
                        },
                    },
                    "session_public_key": self.session_public_jwk(),
                }
            ).encode(),
        )
        assert status == 200, f"register/finish failed: {status} {body}"

    def login(self) -> str:
        status, options = _request(
            "POST",
            f"{self.base_url}/auth/webauthn/login/begin",
            body=json.dumps({"username": self.username}).encode(),
        )
        assert status == 200, f"login/begin failed: {status} {options}"

        challenge = _b64url_decode(options["challenge"])
        self.sign_count += 1
        auth_data = (
            hashlib.sha256(RP_ID.encode()).digest()
            + bytes([0x05])  # UP | UV
            + self.sign_count.to_bytes(4, "big")
        )
        client_data = self._client_data("webauthn.get", challenge)
        signature = self.passkey.sign(
            auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256())
        )
        cred_id = _b64url(self.credential_id)

        status, body = _request(
            "POST",
            f"{self.base_url}/auth/webauthn/login/finish",
            body=json.dumps(
                {
                    "username": self.username,
                    "credential": {
                        "id": cred_id,
                        "rawId": cred_id,
                        "type": "public-key",
                        "response": {
                            "clientDataJSON": _b64url(client_data),
                            "authenticatorData": _b64url(auth_data),
                            "signature": _b64url(signature),
                        },
                    },
                    "session_public_key": self.session_public_jwk(),
                }
            ).encode(),
        )
        assert status == 200, f"login/finish failed: {status} {body}"
        self.session_id = body["session_id"]
        return self.session_id

    # -- a legitimate, correctly-signed request (what Ajay's SDK will do) --

    def signed_transfer(self, payload: dict, mode: str = "protected"):
        status, nonce_body = _request(
            "POST",
            f"{self.base_url}/auth/nonce",
            body=json.dumps({"session_id": self.session_id}).encode(),
        )
        assert status == 200, f"nonce failed: {status} {nonce_body}"

        body = json.dumps(payload).encode()
        self.sequence += 1
        timestamp = _now_iso()
        body_hash = hashlib.sha256(body).hexdigest()

        canonical = "\n".join(
            [
                self.session_id, "POST", RP_ORIGIN, TRANSFER_PATH, body_hash,
                nonce_body["nonce"], str(self.sequence), timestamp,
            ]
        )
        der = self.session_key.sign(canonical.encode(), ec.ECDSA(hashes.SHA256()))
        r, s = asym_utils.decode_dss_signature(der)
        raw_signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")

        envelope = {
            "session_id": self.session_id, "method": "POST", "origin": RP_ORIGIN,
            "path": TRANSFER_PATH, "body_hash": body_hash, "nonce": nonce_body["nonce"],
            "sequence": self.sequence, "timestamp": timestamp,
            "signature": base64.b64encode(raw_signature).decode(),
        }
        proof = base64.b64encode(json.dumps(envelope).encode()).decode()

        status, response = _request(
            "POST",
            f"{self.base_url}{TRANSFER_PATH}?mode={mode}",
            body=body,
            headers={"X-KAAVAL-Proof": proof, "Cookie": f"kaaval_session={self.session_id}"},
        )
        return status, response, {"proof": proof, "body": body}


# --- the attacker ------------------------------------------------------

class AttackerConsole:
    """Holds ONLY what an AiTM proxy could actually capture."""

    def __init__(self, base_url: str, stolen_cookie: str):
        self.base_url = base_url.rstrip("/")
        self.stolen_cookie = stolen_cookie

    def replay_cookie(self, payload: dict, mode: str):
        """The classic attack: present the stolen cookie, nothing else."""
        return _request(
            "POST",
            f"{self.base_url}{TRANSFER_PATH}?mode={mode}",
            body=json.dumps(payload).encode(),
            headers={"Cookie": f"kaaval_session={self.stolen_cookie}"},
        )

    def replay_captured_request(self, captured: dict, mode: str):
        """Replay a genuine signed request verbatim, exactly as sniffed."""
        return _request(
            "POST",
            f"{self.base_url}{TRANSFER_PATH}?mode={mode}",
            body=captured["body"],
            headers={
                "X-KAAVAL-Proof": captured["proof"],
                "Cookie": f"kaaval_session={self.stolen_cookie}",
            },
        )

    def tamper_captured_request(self, captured: dict, new_payload: dict, mode: str):
        """Keep the victim's real signature, swap the body underneath it."""
        return _request(
            "POST",
            f"{self.base_url}{TRANSFER_PATH}?mode={mode}",
            body=json.dumps(new_payload).encode(),
            headers={
                "X-KAAVAL-Proof": captured["proof"],
                "Cookie": f"kaaval_session={self.stolen_cookie}",
            },
        )


# --- the demo script ---------------------------------------------------

def _line(char="-"):
    print(char * 74)


def _scene(number, title):
    print()
    _line("=")
    print(f" SCENE {number}: {title}")
    _line("=")


def _outcome(label, status, body, *, expect_ok: bool, expect_reason=None):
    """Print one attack result and say whether it matched expectations."""
    reason = None
    if isinstance(body, dict) and isinstance(body.get("detail"), dict):
        reason = body["detail"].get("reason")

    succeeded = status == 200
    matched = (succeeded == expect_ok) and (expect_reason is None or reason == expect_reason)

    print(f"  {label}")
    print(f"    HTTP {status}  {json.dumps(body)}")
    if succeeded:
        print("    -> TRANSFER WENT THROUGH")
    else:
        print(f"    -> BLOCKED, reason: {reason}")
    print(f"    [{'as expected' if matched else 'UNEXPECTED'}]")
    return matched


def main() -> int:
    parser = argparse.ArgumentParser(description="KAAVAL attacker console (simulated attack, demo only)")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    args = parser.parse_args()

    print()
    _line("#")
    print(" KAAVAL ATTACKER CONSOLE — SIMULATED ATTACK, DEMO ONLY")
    print(f" target: {args.base_url}")
    _line("#")

    username = f"victim-{uuid.uuid4().hex[:8]}@kaaval.local"
    victim = VictimBrowser(args.base_url, username)
    payload = {"to_account": "acct-attacker", "amount": 5000}
    results = []

    _scene(0, "The victim logs in for real (passkey + session key)")
    victim.register()
    session_id = victim.login()
    print(f"  registered and logged in as {username}")
    print(f"  session cookie now in flight: kaaval_session={session_id}")
    print("  the AiTM proxy captures that cookie as it passes through.")
    print("  it CANNOT capture the session private key: that key is")
    print("  non-exportable and never leaves the browser.")

    attacker = AttackerConsole(args.base_url, stolen_cookie=session_id)

    _scene(1, "Stolen cookie replayed — protection OFF (baseline)")
    print("  PRD acceptance criterion 1. This SHOULD succeed: it is the")
    print("  negative control that proves the vulnerability is real.")
    status, body = attacker.replay_cookie(payload, mode="baseline")
    results.append(_outcome("attacker replays the stolen cookie:", status, body, expect_ok=True))

    _scene(2, "The same stolen cookie — protection ON (PulseLock)")
    print("  PRD acceptance criterion 2. Identical request, identical")
    print("  cookie. The cookie is no longer sufficient on its own.")
    status, body = attacker.replay_cookie(payload, mode="protected")
    results.append(
        _outcome("attacker replays the stolen cookie:", status, body,
                 expect_ok=False, expect_reason="proof_absent")
    )

    _scene(3, "The victim's own signed request still works")
    print("  Protection must stop the attacker without stopping the user.")
    status, body, captured = victim.signed_transfer(payload, mode="protected")
    results.append(_outcome("victim sends a signed request:", status, body, expect_ok=True))

    _scene(4, "Captured signed request replayed verbatim")
    print("  PRD acceptance criterion 4. The attacker sniffed a complete,")
    print("  correctly-signed request and resends it unchanged.")
    status, body = attacker.replay_captured_request(captured, mode="protected")
    results.append(
        _outcome("attacker resends the captured request:", status, body,
                 expect_ok=False, expect_reason="nonce_reused")
    )

    _scene(5, "Captured request with the body swapped underneath")
    print("  PRD acceptance criterion 3. The attacker keeps the victim's")
    print("  real signature but rewrites the amount.")
    status, body, captured2 = victim.signed_transfer(payload, mode="protected")
    assert status == 200, "victim's second signed request should have succeeded"
    status, body = attacker.tamper_captured_request(
        captured2, {"to_account": "acct-attacker", "amount": 999999}, mode="protected"
    )
    results.append(
        _outcome("attacker rewrites the amount to 999999:", status, body,
                 expect_ok=False, expect_reason="body_hash_mismatch")
    )

    print()
    _line("=")
    passed = sum(1 for r in results if r)
    print(f" RESULT: {passed}/{len(results)} scenes produced the expected outcome")
    print(" Every block above was decided by deterministic verification —")
    print(" no model, no risk score, no probability. Each one names the")
    print(" exact check it failed, and each is on the event timeline.")
    _line("=")
    print()
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
