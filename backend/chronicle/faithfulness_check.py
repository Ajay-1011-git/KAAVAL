"""Deterministic entity grounding checks for Chronicle explanations."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Mapping, Sequence

if TYPE_CHECKING:
    from backend.contracts import SecurityEvent


logger = logging.getLogger(__name__)

_USER_IDENTIFIER = re.compile(
    r"\buser[-_:][a-z0-9](?:[a-z0-9._:-]*[a-z0-9])?\b",
    re.IGNORECASE,
)
_EMAIL_IDENTIFIER = re.compile(
    r"\b[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+\.[a-z]{2,}\b",
    re.IGNORECASE,
)
_APPLICATION_IDENTIFIER = re.compile(
    r"\bapp[-_:][a-z0-9](?:[a-z0-9._:-]*[a-z0-9])?\b",
    re.IGNORECASE,
)
_REASON_IDENTIFIER = re.compile(r"\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b")


@dataclass(frozen=True)
class FaithfulnessResult:
    is_faithful: bool
    unmatched_users: tuple[str, ...]
    unmatched_applications: tuple[str, ...]
    unmatched_reasons: tuple[str, ...]


def _normalized(values: Sequence[str]) -> set[str]:
    return {value.casefold() for value in values if value}


def _event_values(events: Sequence[SecurityEvent], field: str) -> set[str]:
    return {
        value
        for event in events
        if isinstance((value := getattr(event, field, None)), str) and value
    }


def _detail_tokens(events: Sequence[SecurityEvent]) -> set[str]:
    """Every key and string value inside the events' `detail` dicts.

    The prompt hands the model each event's full `detail` mapping, so a
    summary that names a detail key ("failed_check 5") or quotes a detail
    value is quoting the event verbatim — grounded by definition. Without
    this, the snake_case identifier regex flagged those quotes as invented.
    """
    tokens: set[str] = set()
    for event in events:
        detail = getattr(event, "detail", None)
        if not isinstance(detail, dict):
            continue
        for key, value in detail.items():
            if isinstance(key, str) and key:
                tokens.add(key)
            if isinstance(value, str) and value:
                tokens.add(value)
    return tokens


def _mentioned_identifiers(summary: str, pattern: re.Pattern[str]) -> set[str]:
    return {match.group(0) for match in pattern.finditer(summary)}


def _unmatched(mentioned: set[str], known: set[str]) -> tuple[str, ...]:
    known_normalized = _normalized(tuple(known))
    return tuple(
        sorted(value for value in mentioned if value.casefold() not in known_normalized)
    )


def check_explanation_faithfulness(
    explanation: Mapping[str, object],
    events: Sequence[SecurityEvent],
) -> FaithfulnessResult:
    """Flag named entities and reason identifiers absent from source events."""

    summary_value = explanation.get("summary")
    summary = summary_value if isinstance(summary_value, str) else ""

    known_users = _event_values(events, "user_id")
    known_applications = _event_values(events, "application_id")
    # The _REASON_IDENTIFIER regex matches any snake_case token, so the set it
    # is checked against must cover every snake_case string the events
    # actually contain — not just `reason`. event_type values are verbatim
    # event fields (and the deterministic fallback prints "event_type
    # (reason)" pairs); detail keys and values are handed to the model in the
    # prompt. Checking against `reason` alone flagged all of those as
    # ungrounded, a false positive on text that quotes the events exactly,
    # which would bury the real drift this warning exists to surface
    # (NFR-3 / TNFR-4).
    known_reasons = (
        _event_values(events, "reason")
        | _event_values(events, "event_type")
        | _detail_tokens(events)
    )

    mentioned_users = _mentioned_identifiers(summary, _USER_IDENTIFIER)
    mentioned_users.update(_mentioned_identifiers(summary, _EMAIL_IDENTIFIER))
    affected_user = explanation.get("affected_user")
    if isinstance(affected_user, str) and affected_user:
        mentioned_users.add(affected_user)

    mentioned_applications = _mentioned_identifiers(
        summary, _APPLICATION_IDENTIFIER
    )
    affected_application = explanation.get("affected_application")
    if isinstance(affected_application, str) and affected_application:
        mentioned_applications.add(affected_application)

    named_entities = mentioned_users | mentioned_applications
    mentioned_reasons = {
        reason
        for reason in _mentioned_identifiers(summary, _REASON_IDENTIFIER)
        if not any(
            reason.casefold() in entity.casefold() for entity in named_entities
        )
    }

    unmatched_users = _unmatched(mentioned_users, known_users)
    unmatched_applications = _unmatched(
        mentioned_applications, known_applications
    )
    unmatched_reasons = _unmatched(mentioned_reasons, known_reasons)
    result = FaithfulnessResult(
        is_faithful=not any(
            (unmatched_users, unmatched_applications, unmatched_reasons)
        ),
        unmatched_users=unmatched_users,
        unmatched_applications=unmatched_applications,
        unmatched_reasons=unmatched_reasons,
    )

    if not result.is_faithful:
        logger.warning(
            "Chronicle faithfulness warning: unmatched_users=%s; "
            "unmatched_applications=%s; unmatched_reasons=%s",
            result.unmatched_users,
            result.unmatched_applications,
            result.unmatched_reasons,
        )

    return result
