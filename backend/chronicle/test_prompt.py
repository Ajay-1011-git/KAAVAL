"""Tests for Chronicle's grounded prompt construction."""

from __future__ import annotations

import json
import unittest
from dataclasses import dataclass, field

from backend.chronicle.prompt import build_chronicle_prompt


@dataclass
class SecurityEventFixture:
    event_id: str
    timestamp: str
    event_type: str
    session_id: str | None
    user_id: str | None
    application_id: str | None
    reason: str
    detail: dict[str, str]
    severity: str
    raw_session_token: str = field(default="must-not-enter-the-prompt")


def sample_events() -> list[SecurityEventFixture]:
    return [
        SecurityEventFixture(
            event_id="event-blocked",
            timestamp="2026-09-04T16:05:04Z",
            event_type="request_blocked",
            session_id="session-demo-01",
            user_id="user-demo-01",
            application_id=None,
            reason="nonce_reused",
            detail={"path": "/api/transfer"},
            severity="blocked",
        ),
        SecurityEventFixture(
            event_id="event-bound",
            timestamp="2026-09-04T16:05:00Z",
            event_type="session_bound",
            session_id="session-demo-01",
            user_id="user-demo-01",
            application_id=None,
            reason="session_key_bound",
            detail={"mode": "pulselock"},
            severity="info",
        ),
    ]


class ChroniclePromptTests(unittest.TestCase):
    def test_prompt_contains_only_whitelisted_event_fields(self) -> None:
        prompt = build_chronicle_prompt(sample_events())  # type: ignore[arg-type]
        serialized = prompt.split("SECURITY_EVENTS:\n", maxsplit=1)[1]
        payload = json.loads(serialized)

        expected_fields = {
            "event_id",
            "timestamp",
            "event_type",
            "session_id",
            "user_id",
            "application_id",
            "reason",
            "detail",
            "severity",
        }
        self.assertEqual(set(payload[0]), expected_fields)
        self.assertNotIn("must-not-enter-the-prompt", prompt)

    def test_events_are_serialized_chronologically(self) -> None:
        prompt = build_chronicle_prompt(sample_events())  # type: ignore[arg-type]
        serialized = prompt.split("SECURITY_EVENTS:\n", maxsplit=1)[1]
        payload = json.loads(serialized)

        self.assertEqual(
            [event["event_type"] for event in payload],
            ["session_bound", "request_blocked"],
        )

    def test_prompt_requires_explicit_uncertainty(self) -> None:
        prompt = build_chronicle_prompt(sample_events())  # type: ignore[arg-type]

        self.assertIn('write exactly: "not stated in the events"', prompt)
        # Remediation is deterministic and attached by KAAVAL, so the prompt
        # must tell the model not to author any (PRD FR-13, NFR-3).
        self.assertIn(
            "suggested_remediation must always be an empty list",
            prompt,
        )
        self.assertIn("do not write remediation advice", prompt)

    def test_empty_event_sequence_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "At least one security event"):
            build_chronicle_prompt([])

    def test_non_string_detail_value_is_rejected(self) -> None:
        event = sample_events()[0]
        event.detail = {"attempt_count": 2}  # type: ignore[dict-item]

        with self.assertRaisesRegex(ValueError, "only string values"):
            build_chronicle_prompt([event])  # type: ignore[list-item]


if __name__ == "__main__":
    unittest.main()
