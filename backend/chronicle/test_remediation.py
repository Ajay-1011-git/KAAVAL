"""Tests for deterministic remediation (PRD FR-13).

The bug these guard against: `suggested_remediation` was grounded against a
`remediation` key inside each event's `detail` dict, but no module anywhere
in the backend ever writes such a key. The grounded set was therefore always
empty, so a live explanation could never carry a remedy — and if the model
offered one it was rejected as ungrounded, silently dropping the whole
explanation to the fallback path.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from backend.chronicle.remediation import (
    build_remediation,
    known_reasons,
    remediation_for_reason,
)
from backend.contracts import SecurityEvent

BACKEND_ROOT = Path(__file__).resolve().parent.parent


def _event(reason: str, event_type: str = "request_blocked") -> SecurityEvent:
    return SecurityEvent(
        event_id=f"event-{reason}",
        timestamp="2026-09-04T16:05:00Z",
        event_type=event_type,
        session_id="session-1",
        user_id="user-1",
        application_id=None,
        reason=reason,
        detail={},
        severity="blocked",
    )


class RemediationTableTests(unittest.TestCase):
    def test_every_blocked_verification_reason_has_a_remedy(self):
        """The seven checks in TRD §6.1, plus a missing proof."""
        for reason in (
            "session_inactive",
            "signature_invalid",
            "request_mismatch",
            "body_hash_mismatch",
            "nonce_reused",
            "sequence_invalid",
            "timestamp_stale",
            "proof_absent",
        ):
            with self.subTest(reason=reason):
                remedy = remediation_for_reason(reason)
                self.assertIsInstance(remedy, str)
                self.assertTrue(remedy.strip())

    def test_every_guardian_block_reason_has_a_remedy(self):
        for reason in (
            "unverified_publisher_with_offline_access_scope",
            "unverified_publisher_with_high_risk_scope",
            "application_not_allowlisted",
            "device_not_registered",
            "code_not_short_lived",
            "sensitive_resource_without_admin_approval",
        ):
            with self.subTest(reason=reason):
                self.assertTrue((remediation_for_reason(reason) or "").strip())

    def test_a_successful_outcome_suggests_nothing(self):
        for reason in (
            "all_checks_passed",
            "webauthn_login_success",
            "publisher_verified",
            "policy_conditions_satisfied",
        ):
            with self.subTest(reason=reason):
                self.assertIsNone(remediation_for_reason(reason))

    def test_an_unrecognised_reason_yields_nothing_rather_than_guessing(self):
        self.assertIsNone(remediation_for_reason("some_reason_we_never_emit"))


class RemediationBuildTests(unittest.TestCase):
    def test_a_replay_incident_produces_its_remedy(self):
        events = [
            _event("nonce_reused", "replay_attempted"),
            _event("nonce_reused", "request_blocked"),
        ]
        steps = build_remediation(events)
        # Both events share a reason, so the operator is told once, not twice.
        self.assertEqual(steps, [remediation_for_reason("nonce_reused")])

    def test_distinct_reasons_accumulate_in_incident_order(self):
        events = [_event("proof_absent"), _event("body_hash_mismatch")]
        self.assertEqual(
            build_remediation(events),
            [
                remediation_for_reason("proof_absent"),
                remediation_for_reason("body_hash_mismatch"),
            ],
        )

    def test_an_all_clear_incident_suggests_nothing(self):
        events = [_event("all_checks_passed", "request_allowed")]
        self.assertEqual(build_remediation(events), [])


class ReasonCoverageTests(unittest.TestCase):
    """Every reason the backend can actually emit must be accounted for.

    This is the regression guard: adding a new `reason` anywhere without a
    remediation entry silently reintroduces "no remedy is ever produced" for
    that incident shape.
    """

    def _emitted_reasons(self) -> set[str]:
        """Scrape `reason=` / `reason,` literals out of the event writers."""
        sources = [
            BACKEND_ROOT / "gateway" / "verify.py",
            BACKEND_ROOT / "gateway" / "demo_app_routes.py",
            BACKEND_ROOT / "gateway" / "webauthn_routes.py",
            BACKEND_ROOT / "guardian" / "oauth_policy.py",
            BACKEND_ROOT / "guardian" / "device_code_policy.py",
        ]
        found: set[str] = set()
        for path in sources:
            text = path.read_text(encoding="utf-8")
            # reason="..." in SecurityEvent construction
            found.update(re.findall(r'reason=["\']([a-z][a-z0-9_]+)["\']', text))
            # the reason half of a policy's (decision, reason) return
            found.update(
                re.findall(r'return\s+"(?:allow|block)",\s*"([a-z][a-z0-9_]+)"', text)
            )
            # verify.py's _EVENT_TYPE_BY_REASON keys are the canonical list
            if path.name == "verify.py":
                table = re.search(
                    r"_EVENT_TYPE_BY_REASON = \{(.*?)\}", text, re.DOTALL
                )
                if table:
                    found.update(re.findall(r'"([a-z_]+)":', table.group(1)))
        return found

    def test_every_emitted_reason_is_known_to_the_remediation_table(self):
        emitted = self._emitted_reasons()
        self.assertTrue(emitted, "scraper found no reasons — it has drifted")

        unknown = sorted(emitted - known_reasons())
        self.assertEqual(
            unknown,
            [],
            "these reasons are emitted by the backend but have no entry in "
            f"backend/chronicle/remediation.py: {unknown}",
        )
        print(f"REASONS COVERED: {len(emitted)} emitted, all mapped")


if __name__ == "__main__":
    unittest.main()
