"""Tests for Chronicle explanation faithfulness checks."""

from __future__ import annotations

import unittest
from types import SimpleNamespace

from backend.chronicle.faithfulness_check import (
    check_explanation_faithfulness,
)


def source_events() -> list[SimpleNamespace]:
    return [
        SimpleNamespace(
            user_id="user-demo-01",
            application_id="app-004",
            reason="nonce_reused",
        )
    ]


class FaithfulnessCheckTests(unittest.TestCase):
    def test_grounded_summary_passes(self) -> None:
        explanation = {
            "summary": (
                "The request for user-demo-01 and app-004 was blocked. "
                "The recorded reason was nonce_reused."
            ),
            "affected_user": "user-demo-01",
            "affected_application": "app-004",
        }

        result = check_explanation_faithfulness(
            explanation,
            source_events(),  # type: ignore[arg-type]
        )

        self.assertTrue(result.is_faithful)
        self.assertEqual(result.unmatched_users, ())
        self.assertEqual(result.unmatched_applications, ())
        self.assertEqual(result.unmatched_reasons, ())

    def test_invented_entities_and_reason_are_flagged(self) -> None:
        explanation = {
            "summary": (
                "user-invented used app-999 and the reason was token_stolen."
            ),
            "affected_user": "user-invented",
            "affected_application": "app-999",
        }

        with self.assertLogs(
            "backend.chronicle.faithfulness_check", level="WARNING"
        ) as captured:
            result = check_explanation_faithfulness(
                explanation,
                source_events(),  # type: ignore[arg-type]
            )

        self.assertFalse(result.is_faithful)
        self.assertEqual(result.unmatched_users, ("user-invented",))
        self.assertEqual(result.unmatched_applications, ("app-999",))
        self.assertEqual(result.unmatched_reasons, ("token_stolen",))
        self.assertIn("Chronicle faithfulness warning", captured.output[0])

    def test_natural_language_without_named_entities_passes(self) -> None:
        explanation = {
            "summary": "A request was blocked for the reason recorded in the event.",
            "affected_user": None,
            "affected_application": None,
        }

        result = check_explanation_faithfulness(
            explanation,
            source_events(),  # type: ignore[arg-type]
        )

        self.assertTrue(result.is_faithful)


if __name__ == "__main__":
    unittest.main()
