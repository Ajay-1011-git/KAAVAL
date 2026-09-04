"""Construct grounded Chronicle prompts from canonical security events."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Sequence

if TYPE_CHECKING:
    from backend.contracts import SecurityEvent


_EVENT_FIELDS = (
    "event_id",
    "timestamp",
    "event_type",
    "session_id",
    "user_id",
    "application_id",
    "reason",
    "detail",
    "severity",
)


def _event_payload(event: SecurityEvent) -> dict[str, object]:
    """Copy only fields permitted by the frozen SecurityEvent contract."""

    payload: dict[str, object] = {}
    for field in _EVENT_FIELDS:
        if not hasattr(event, field):
            raise ValueError(f"Security event is missing required field: {field}")
        payload[field] = getattr(event, field)

    detail = payload["detail"]
    if not isinstance(detail, dict) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in detail.items()
    ):
        raise ValueError("Security event detail must contain only string values")

    return payload


def build_chronicle_prompt(events: Sequence[SecurityEvent]) -> str:
    """Build a bounded prompt using only fields from the supplied events."""

    if not events:
        raise ValueError("At least one security event is required")

    event_payloads = sorted(
        (_event_payload(event) for event in events),
        key=lambda event: str(event["timestamp"]),
    )
    serialized_events = json.dumps(
        event_payloads,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )

    return f"""You are Chronicle, a post-decision incident narrator.

Write a concise incident explanation using only facts explicitly present in SECURITY_EVENTS below.

Grounding rules:
- Do not infer intent, identity, cause, location, device, impact, or outcome beyond the supplied fields.
- Do not add outside security knowledge or unstated best practices.
- If a requested fact is absent, write exactly: \"not stated in the events\".
- affected_user must be a supplied user_id or null.
- affected_application must be a supplied application_id or null.
- suggested_remediation must always be an empty list. Remediation is attached deterministically by KAAVAL from the recorded reason; do not write remediation advice.
- Describe the recorded decision; do not claim that Chronicle made, changed, or reversed it.

Return only a JSON object with these keys:
{{
  \"summary\": \"plain-language paragraph\",
  \"affected_user\": null,
  \"affected_application\": null,
  \"suggested_remediation\": []
}}

SECURITY_EVENTS:
{serialized_events}"""
