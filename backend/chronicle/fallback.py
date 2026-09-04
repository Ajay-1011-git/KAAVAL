"""Deterministic Chronicle narratives for demo and outage fallback paths.

Remediation comes from backend/chronicle/remediation.py rather than being
hardcoded per branch, so the live and fallback paths give the operator the
same advice for the same incident (PRD FR-13).
""" 

from __future__ import annotations

from typing import TYPE_CHECKING, Sequence

from backend.chronicle.remediation import build_remediation

if TYPE_CHECKING:
    from backend.contracts import SecurityEvent


REPLAY_REASON = "nonce_reused"
OAUTH_OFFLINE_ACCESS_REASON = (
    "unverified_publisher_with_offline_access_scope"
)


def _single_value(events: Sequence[SecurityEvent], field: str) -> str | None:
    values = {
        value
        for event in events
        if (value := getattr(event, field, None)) is not None
    }
    return next(iter(values)) if len(values) == 1 else None


def _base_payload(
    events: Sequence[SecurityEvent],
    incident_id: str,
    generated_at: str,
) -> dict[str, object]:
    if not events:
        raise ValueError("At least one security event is required")
    if not incident_id:
        raise ValueError("incident_id is required")
    if not generated_at:
        raise ValueError("generated_at is required")

    event_ids = [getattr(event, "event_id", None) for event in events]
    if not all(isinstance(event_id, str) and event_id for event_id in event_ids):
        raise ValueError("Every security event must have an event_id")

    return {
        "incident_id": incident_id,
        "related_event_ids": event_ids,
        "affected_user": _single_value(events, "user_id"),
        "affected_application": _single_value(events, "application_id"),
        "generated_at": generated_at,
    }


def _is_event(event: SecurityEvent, event_type: str, reason: str) -> bool:
    return (
        getattr(event, "event_type", None) == event_type
        and getattr(event, "reason", None) == reason
    )


def build_fallback_explanation(
    events: Sequence[SecurityEvent],
    incident_id: str,
    generated_at: str,
) -> dict[str, object]:
    """Return an IncidentExplanation-shaped payload without an LLM call."""

    payload = _base_payload(events, incident_id, generated_at)

    replay_attempted = any(
        _is_event(event, "replay_attempted", REPLAY_REASON)
        for event in events
    )
    replay_blocked = any(
        _is_event(event, "request_blocked", REPLAY_REASON)
        for event in events
    )
    oauth_blocked = any(
        _is_event(
            event,
            "oauth_grant_blocked",
            OAUTH_OFFLINE_ACCESS_REASON,
        )
        for event in events
    )

    if replay_attempted and replay_blocked:
        payload.update(
            {
                "summary": (
                    "KAAVAL recorded a replay attempt and blocked the related "
                    f"request. The recorded reason was {REPLAY_REASON}."
                ),
                "suggested_remediation": build_remediation(events),
            }
        )
        return payload

    if oauth_blocked:
        payload.update(
            {
                "summary": (
                    "Guardian recorded an OAuth grant block. The recorded reason "
                    f"was {OAUTH_OFFLINE_ACCESS_REASON}."
                ),
                "suggested_remediation": build_remediation(events),
            }
        )
        return payload

    recorded_events = ", ".join(
        f"{getattr(event, 'event_type', 'not stated')} "
        f"({getattr(event, 'reason', 'not stated')})"
        for event in events
    )
    payload.update(
        {
            "summary": f"The referenced events recorded: {recorded_events}.",
            "suggested_remediation": build_remediation(events),
        }
    )
    return payload
