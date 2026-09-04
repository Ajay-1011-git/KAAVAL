"""Tests for the Chronicle explanation endpoint."""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import unittest
from contextlib import contextmanager
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.chronicle import routes


def replay_events() -> list[SimpleNamespace]:
    return [
        SimpleNamespace(
            event_id="event-replay",
            timestamp="2026-09-04T16:05:03Z",
            event_type="replay_attempted",
            session_id="session-demo-01",
            user_id="user-demo-01",
            application_id=None,
            reason="nonce_reused",
            detail={"path": "/api/transfer"},
            severity="warning",
        ),
        SimpleNamespace(
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
    ]


class ChronicleRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        app = FastAPI()
        app.include_router(routes.router)
        self.client = TestClient(app)

    @patch("backend.chronicle.routes._fetch_events", return_value=replay_events())
    def test_forced_fallback_returns_header_and_payload(self, _fetch: object) -> None:
        with patch.dict(os.environ, {"CHRONICLE_FALLBACK_MODE": "true"}, clear=False):
            response = self.client.post(
                "/chronicle/explain",
                json={"event_ids": ["event-replay", "event-blocked"]},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-KAAVAL-Chronicle-Mode"], "fallback")
        self.assertIn("nonce_reused", response.json()["summary"])

    @patch("backend.chronicle.routes._fetch_events", return_value=replay_events())
    @patch(
        "backend.chronicle.routes._call_anthropic",
        new_callable=AsyncMock,
        return_value=json.dumps(
            {
                "summary": "The request was blocked with reason nonce_reused.",
                "affected_user": "user-demo-01",
                "affected_application": None,
                "suggested_remediation": [],
            }
        ),
    )
    def test_live_response_is_parsed_into_contract(
        self, call_anthropic: AsyncMock, _fetch: object
    ) -> None:
        environment = {
            "CHRONICLE_FALLBACK_MODE": "false",
            "ANTHROPIC_API_KEY": "test-key",
            "CHRONICLE_LLM_MODEL": "configured-test-model",
        }
        with patch.dict(os.environ, environment, clear=False):
            response = self.client.post(
                "/chronicle/explain",
                json={"event_ids": ["event-replay", "event-blocked"]},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-KAAVAL-Chronicle-Mode"], "live")
        self.assertEqual(
            response.json()["related_event_ids"],
            ["event-replay", "event-blocked"],
        )
        call_anthropic.assert_awaited_once()

    @patch("backend.chronicle.routes._fetch_events", return_value=replay_events())
    @patch(
        "backend.chronicle.routes._call_anthropic",
        new_callable=AsyncMock,
        side_effect=TimeoutError,
    )
    def test_timeout_uses_fallback(
        self, _call_anthropic: AsyncMock, _fetch: object
    ) -> None:
        environment = {
            "CHRONICLE_FALLBACK_MODE": "false",
            "ANTHROPIC_API_KEY": "test-key",
            "CHRONICLE_LLM_MODEL": "configured-test-model",
        }
        with patch.dict(os.environ, environment, clear=False):
            response = self.client.post(
                "/chronicle/explain",
                json={"event_ids": ["event-replay", "event-blocked"]},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-KAAVAL-Chronicle-Mode"], "fallback")

    @patch("backend.chronicle.routes._fetch_events", return_value=replay_events())
    @patch(
        "backend.chronicle.routes._call_anthropic",
        new_callable=AsyncMock,
        return_value="not valid JSON",
    )
    def test_malformed_live_output_uses_fallback(
        self, _call_anthropic: AsyncMock, _fetch: object
    ) -> None:
        environment = {
            "CHRONICLE_FALLBACK_MODE": "false",
            "ANTHROPIC_API_KEY": "test-key",
            "CHRONICLE_LLM_MODEL": "configured-test-model",
        }
        with patch.dict(os.environ, environment, clear=False):
            response = self.client.post(
                "/chronicle/explain",
                json={"event_ids": ["event-replay", "event-blocked"]},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-KAAVAL-Chronicle-Mode"], "fallback")

    def test_duplicate_event_ids_are_rejected(self) -> None:
        response = self.client.post(
            "/chronicle/explain",
            json={"event_ids": ["event-replay", "event-replay"]},
        )

        self.assertEqual(response.status_code, 422)

    def test_unknown_user_from_live_response_is_rejected(self) -> None:
        response = json.dumps(
            {
                "summary": "A request was blocked.",
                "affected_user": "invented-user",
                "affected_application": None,
                "suggested_remediation": [],
            }
        )

        with self.assertRaisesRegex(ValueError, "unknown user"):
            routes._parse_live_explanation(
                response,
                replay_events(),  # type: ignore[arg-type]
                "incident-01",
                "2026-09-04T16:10:00Z",
            )


class DatabaseLoadingTests(unittest.TestCase):
    def test_events_are_loaded_in_requested_order(self) -> None:
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        connection.execute(
            """
            CREATE TABLE events (
                event_id TEXT, timestamp TEXT, event_type TEXT,
                session_id TEXT, user_id TEXT, application_id TEXT,
                reason TEXT, detail TEXT, severity TEXT
            )
            """
        )
        for event_value in replay_events():
            connection.execute(
                "INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event_value.event_id,
                    event_value.timestamp,
                    event_value.event_type,
                    event_value.session_id,
                    event_value.user_id,
                    event_value.application_id,
                    event_value.reason,
                    json.dumps(event_value.detail),
                    event_value.severity,
                ),
            )

        @contextmanager
        def db_session():
            yield connection

        contracts_module = ModuleType("backend.contracts")
        contracts_module.SecurityEvent = lambda **values: SimpleNamespace(**values)
        db_module = ModuleType("backend.db")
        db_module.db_session = db_session

        with patch.dict(
            sys.modules,
            {
                "backend.contracts": contracts_module,
                "backend.db": db_module,
            },
        ):
            events = routes._fetch_events(["event-blocked", "event-replay"])

        self.assertEqual(
            [event.event_id for event in events],
            ["event-blocked", "event-replay"],
        )
        self.assertEqual(events[0].detail, {"path": "/api/transfer"})


class AnthropicSdkShapeTests(unittest.IsolatedAsyncioTestCase):
    async def test_async_messages_call_uses_configured_timeout_and_model(self) -> None:
        response = SimpleNamespace(
            content=[SimpleNamespace(type="text", text='{"summary":"ok"}')]
        )
        create = AsyncMock(return_value=response)
        client_options: dict[str, object] = {}

        class FakeClient:
            def __init__(self, **options: object) -> None:
                client_options.update(options)
                self.messages = SimpleNamespace(create=create)

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args: object) -> None:
                return None

        import anthropic

        with (
            patch.object(anthropic, "AsyncAnthropic", FakeClient),
            patch.dict(
                os.environ,
                {"CHRONICLE_LLM_TIMEOUT_SECONDS": "4.5"},
                clear=False,
            ),
        ):
            text = await routes._call_anthropic(
                "grounded prompt", "test-key", "configured-test-model"
            )

        self.assertEqual(text, '{"summary":"ok"}')
        self.assertEqual(
            client_options,
            {"api_key": "test-key", "timeout": 4.5, "max_retries": 0},
        )
        create.assert_awaited_once_with(
            model="configured-test-model",
            max_tokens=routes.MAX_OUTPUT_TOKENS,
            messages=[{"role": "user", "content": "grounded prompt"}],
        )


if __name__ == "__main__":
    unittest.main()
