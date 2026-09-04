#!/usr/bin/env python3
"""
=============================================================================
 KAAVAL GUARDIAN CONSOLE  —  SIMULATED OAUTH / DEVICE-CODE REQUESTS, DEMO ONLY
=============================================================================

Amendment FIX-5. Guardian's policy and endpoints were real and unit-tested,
but nothing fired them live: the "malicious OAuth consent request is blocked
with a stated policy reason" claim (PRD acceptance criterion 6) was only ever
demonstrated inside a test file.

This drives the real endpoints over HTTP, showing BOTH directions so the
policy reads as a policy rather than a blanket deny:

  scene 1  malicious OAuth consent  -> blocked, with the failing condition named
  scene 2  clean OAuth consent      -> allowed
  scene 3  malicious device code    -> blocked
  scene 4  compliant device code    -> allowed

Every decision below is deterministic if/else policy (PRD FR-11). There is no
model, no score, and no probability anywhere in this path — the reason string
each block returns is the literal name of the condition that failed.

The applications described here are fabricated demo inputs, clearly labelled
as such; there is no real publisher registry behind them.

Usage:
    python -m backend.attacker_console.oauth_consent [--base-url http://127.0.0.1:8000]

Exits non-zero if any scene did not produce its expected decision, so it
doubles as a pre-demo smoke check.
"""

import argparse
import json
import sys
import urllib.error
import urllib.request

OAUTH_PATH = "/guardian/oauth/evaluate"
DEVICE_CODE_PATH = "/guardian/device-code/evaluate"


def _post(base_url: str, path: str, payload: dict) -> tuple[int, dict]:
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}{path}",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request) as response:
            return response.status, json.loads(response.read() or b"null")
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            return error.code, json.loads(raw or b"null")
        except json.JSONDecodeError:
            return error.code, {"raw": raw.decode(errors="replace")}


# --- fabricated demo inputs -------------------------------------------

MALICIOUS_OAUTH = {
    "application_id": "app-consent-phish-01",
    "application_name": "Docs Sync Helper",
    "publisher_verified": False,
    "requested_scopes": ["Mail.ReadWrite", "Files.ReadWrite.All", "offline_access"],
    "redirect_uri": "https://docs-sync-helper.example/callback",
    "offline_access_requested": True,
    "is_org_allowlisted": False,
}

CLEAN_OAUTH = {
    "application_id": "app-approved-crm-01",
    "application_name": "Approved CRM",
    "publisher_verified": True,
    "requested_scopes": ["User.Read"],
    "redirect_uri": "https://crm.corp.example/callback",
    "offline_access_requested": False,
    "is_org_allowlisted": True,
}

MALICIOUS_DEVICE_CODE = {
    "application_id": "app-device-phish-01",
    "device_registered": False,
    "code_ttl_seconds": 900,
    "is_allowlisted": False,
    "is_sensitive_resource": True,
    "admin_approved": False,
}

COMPLIANT_DEVICE_CODE = {
    "application_id": "app-conference-room-01",
    "device_registered": True,
    "code_ttl_seconds": 60,
    "is_allowlisted": True,
    "is_sensitive_resource": False,
    "admin_approved": True,
}


def _line(char: str = "-") -> None:
    print(char * 74)


def _scene(number: int, title: str) -> None:
    print()
    _line("=")
    print(f" SCENE {number}: {title}")
    _line("=")


def _outcome(label: str, status: int, body: dict, *, expect: str) -> bool:
    decision = body.get("decision") if isinstance(body, dict) else None
    reason = body.get("reason") if isinstance(body, dict) else None
    matched = status == 200 and decision == expect

    print(f"  {label}")
    print(f"    HTTP {status}  {json.dumps(body)}")
    print(f"    -> decision: {decision}")
    print(f"    -> policy reason: {reason}")
    print(f"    [{'as expected' if matched else 'UNEXPECTED'}]")
    return matched


def main() -> int:
    parser = argparse.ArgumentParser(
        description="KAAVAL Guardian console (simulated requests, demo only)"
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    args = parser.parse_args()

    print()
    _line("#")
    print(" KAAVAL GUARDIAN CONSOLE — SIMULATED REQUESTS, DEMO ONLY")
    print(f" target: {args.base_url}")
    _line("#")

    results = []

    _scene(1, "Malicious OAuth consent request")
    print("  PRD acceptance criterion 6. Unverified publisher, mailbox")
    print("  read/write, and offline access — the classic consent-phishing")
    print("  shape. Guardian must block it and say exactly why.")
    status, body = _post(args.base_url, OAUTH_PATH, MALICIOUS_OAUTH)
    results.append(_outcome("attacker requests consent:", status, body, expect="block"))

    _scene(2, "Legitimate OAuth consent request")
    print("  The control. A verified, allowlisted app asking for one narrow")
    print("  scope must still be allowed — a policy that blocks everything")
    print("  proves nothing.")
    status, body = _post(args.base_url, OAUTH_PATH, CLEAN_OAUTH)
    results.append(_outcome("approved app requests consent:", status, body, expect="allow"))

    _scene(3, "Malicious device-code request")
    print("  Device code is blocked BY DEFAULT (PRD FR-9); an unregistered")
    print("  device asking for a sensitive resource fails on the first")
    print("  unmet condition.")
    status, body = _post(args.base_url, DEVICE_CODE_PATH, MALICIOUS_DEVICE_CODE)
    results.append(_outcome("attacker starts device-code flow:", status, body, expect="block"))

    _scene(4, "Compliant device-code request")
    print("  The narrow exception the policy actually permits: allowlisted,")
    print("  registered device, short-lived code, admin approved.")
    status, body = _post(args.base_url, DEVICE_CODE_PATH, COMPLIANT_DEVICE_CODE)
    results.append(_outcome("conference room device enrolls:", status, body, expect="allow"))

    print()
    _line("=")
    passed = sum(1 for result in results if result)
    print(f" RESULT: {passed}/{len(results)} scenes produced the expected decision")
    print(" Each decision above is deterministic if/else policy — no model, no")
    print(" score. Every one is now on the live event feed, and any of them can")
    print(" be handed to Chronicle for a plain-language explanation.")
    _line("=")
    print()
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
