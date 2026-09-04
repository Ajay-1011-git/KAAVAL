"""Tests for deterministic Chronicle fallback narratives."""

from __future__ import annotations

import unittest
from types import SimpleNamespace

from backend.chronicle.remediation import remediation_for_reason
from backend.chronicle.fallback import (
    OAUTH_OFFLINE_ACCESS_REASON,
    REPLAY_REASON,
    build_fallback_explanation,
)


GENERATED_AT = "2026-09-04T16:10:00Z"


def event(
    event_id: str,
    event_type: str,
    reason: str,
    *,
    session_id: str | None = None,
    user_id: str | None = None,
    application_id: str | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        event_id=event_id,
        event_type=event_type,
        reason=reason,
        session_id=session_id,
        user_id=user_id,
        application_id=application_id,
    )


class ChronicleFallbackTests(unittest.TestCase):
    def test_replayed_cookie_narrative_uses_actual_reason(self) -> None:
        events = [
            event(
                "event-replay",
                "replay_attempted",
                REPLAY_REASON,
                session_id="session-demo-01",
                user_id="user-demo-01",
            ),
            event(
                "event-blocked",
                "request_blocked",
                REPLAY_REASON,
                session_id="session-demo-01",
                user_id="user-demo-01",
            ),
        ]

        explanation = build_fallback_explanation(
            events,  # type: ignore[arg-type]
            "incident-replay",
            GENERATED_AT,
        )

        self.assertIn(REPLAY_REASON, explanation["summary"])
        self.assertEqual(
            explanation["related_event_ids"],
            ["event-replay", "event-blocked"],
        )
        self.assertEqual(explanation["affected_user"], "user-demo-01")
        self.assertIsNone(explanation["affected_application"])
        self.assertEqual(len(explanation["suggested_remediation"]), 1)

    def test_blocked_oauth_narrative_uses_guardian_reason(self) -> None:
        events = [
            event(
                "event-oauth",
                "oauth_grant_blocked",
                OAUTH_OFFLINE_ACCESS_REASON,
                application_id="app-004",
            )
        ]

        explanation = build_fallback_explanation(
            events,  # type: ignore[arg-type]
            "incident-oauth",
            GENERATED_AT,
        )

        self.assertIn(OAUTH_OFFLINE_ACCESS_REASON, explanation["summary"])
        self.assertEqual(explanation["affected_application"], "app-004")
        self.assertIsNone(explanation["affected_user"])
        self.assertEqual(len(explanation["suggested_remediation"]), 1)

    def test_unknown_incident_remains_grounded(self) -> None:
        events = [
            event(
                "event-unknown",
                "signature_invalid",
                "signature_invalid",
                session_id="session-demo-02",
            )
        ]

        explanation = build_fallback_explanation(
            events,  # type: ignore[arg-type]
            "incident-unknown",
            GENERATED_AT,
        )

        self.assertEqual(
            explanation["summary"],
            "The referenced events recorded: signature_invalid (signature_invalid).",
        )
        # The narrative is the generic one because this incident shape has no
        # scripted branch, but remediation is still deterministic and specific
        # to the recorded reason (PRD FR-13) — it is keyed off `reason`, not
        # off which narrative branch matched.
        self.assertEqual(
            explanation["suggested_remediation"],
            [remediation_for_reason("signature_invalid")],
        )

    def test_conflicting_affected_entities_are_not_attributed(self) -> None:
        events = [
            event("event-1", "request_blocked", "request_mismatch", user_id="user-1"),
            event("event-2", "request_blocked", "request_mismatch", user_id="user-2"),
        ]

        explanation = build_fallback_explanation(
            events,  # type: ignore[arg-type]
            "incident-multiple-users",
            GENERATED_AT,
        )

        self.assertIsNone(explanation["affected_user"])

    def test_empty_event_sequence_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "At least one security event"):
            build_fallback_explanation([], "incident-empty", GENERATED_AT)


if __name__ == "__main__":
    unittest.main()
