"""FastAPI endpoint for grounded, post-decision Chronicle explanations.

The live narrator runs on Groq; an unset key, an unset model, a timeout, or
any ungrounded response falls back to the deterministic narrative in
backend/chronicle/fallback.py.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Sequence

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from backend.chronicle.faithfulness_check import check_explanation_faithfulness
from backend.chronicle.fallback import build_fallback_explanation
from backend.chronicle.prompt import build_chronicle_prompt

if TYPE_CHECKING:
    from backend.contracts import SecurityEvent


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/chronicle", tags=["chronicle"])

MAX_EVENT_IDS = 50
DEFAULT_TIMEOUT_SECONDS = 5.0
# Headroom, not output size. Chronicle's JSON is ~150 tokens, but the default
# model is a REASONING model whose thinking tokens are billed against this
# same ceiling. At 512 the reasoning alone consumed 513 tokens and Groq
# rejected the turn with json_validate_failed ("max completion tokens reached
# before generating a valid document") — measured, not guessed.
MAX_OUTPUT_TOKENS = 2048

# Groq model used when CHRONICLE_LLM_MODEL is unset. Confirmed available on
# this project's Groq account by listing GET /openai/v1/models in-session,
# rather than assuming a model id from memory.
DEFAULT_MODEL = "openai/gpt-oss-120b"

# Chronicle's task is mechanical, grounded summarisation, so the reasoning
# budget is deliberately small: it keeps the call inside
# CHRONICLE_LLM_TIMEOUT_SECONDS and well under MAX_OUTPUT_TOKENS. Set
# CHRONICLE_LLM_REASONING_EFFORT to "" to omit the parameter entirely, which
# is what a non-reasoning model needs.
DEFAULT_REASONING_EFFORT = "low"


class ExplainRequest(BaseModel):
    event_ids: list[str]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_fallback_forced() -> bool:
    return os.getenv("CHRONICLE_FALLBACK_MODE", "false").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _live_configuration() -> tuple[str, str] | None:
    """Resolve Groq credentials, or None to run the deterministic fallback.

    GROQ_API_KEY is the name the Groq SDK itself reads; GROQ_API is accepted
    as an alias, and LLM_API_KEY stays the generic name the build documents
    use. A missing key or model is not an error — Chronicle is designed to
    degrade to build_fallback_explanation rather than fail (TNFR-4).
    """
    # .strip() throughout: a key present-but-blank in .env (the shape
    # .env.example ships) must read as "unset" and take the fallback, not as
    # a live call with an empty credential. Likewise a blank model means
    # "use the default", not "disable the live path".
    api_key = (
        os.getenv("GROQ_API_KEY", "").strip()
        or os.getenv("GROQ_API", "").strip()
        or os.getenv("LLM_API_KEY", "").strip()
    )
    model = os.getenv("CHRONICLE_LLM_MODEL", "").strip() or DEFAULT_MODEL
    if not api_key:
        return None
    return api_key, model


def _mode_headers(mode: str) -> dict[str, str]:
    return {
        "X-KAAVAL-Chronicle-Mode": mode,
        "Access-Control-Expose-Headers": "X-KAAVAL-Chronicle-Mode",
    }


def _explanation_response(
    explanation: dict[str, object],
    events: Sequence[SecurityEvent],
    mode: str,
) -> JSONResponse:
    check_explanation_faithfulness(explanation, events)
    return JSONResponse(explanation, headers=_mode_headers(mode))


def _validate_event_ids(event_ids: list[str]) -> None:
    if not event_ids:
        raise HTTPException(status_code=422, detail="event_ids must not be empty")
    if len(event_ids) > MAX_EVENT_IDS:
        raise HTTPException(
            status_code=422,
            detail=f"event_ids must contain at most {MAX_EVENT_IDS} entries",
        )
    if any(not event_id.strip() for event_id in event_ids):
        raise HTTPException(
            status_code=422,
            detail="event_ids must contain non-empty strings",
        )
    if len(set(event_ids)) != len(event_ids):
        raise HTTPException(status_code=422, detail="event_ids must be unique")


def _fetch_events(event_ids: list[str]) -> list[SecurityEvent]:
    """Load canonical events while preserving the caller's requested order."""

    from backend.contracts import SecurityEvent
    from backend.db import db_session

    placeholders = ",".join("?" for _ in event_ids)
    with db_session() as connection:
        rows = connection.execute(
            f"""
            SELECT event_id, timestamp, event_type, session_id, user_id,
                   application_id, reason, detail, severity
            FROM events
            WHERE event_id IN ({placeholders})
            """,
            event_ids,
        ).fetchall()

    events_by_id: dict[str, SecurityEvent] = {}
    for row in rows:
        values = dict(row)
        try:
            values["detail"] = json.loads(values["detail"])
            event = SecurityEvent(**values)
        except (json.JSONDecodeError, TypeError, ValueError) as error:
            raise HTTPException(
                status_code=500,
                detail="A referenced security event is malformed",
            ) from error
        events_by_id[event.event_id] = event

    missing_ids = [event_id for event_id in event_ids if event_id not in events_by_id]
    if missing_ids:
        raise HTTPException(
            status_code=404,
            detail={"message": "Security events not found", "event_ids": missing_ids},
        )

    return [events_by_id[event_id] for event_id in event_ids]


async def _call_groq(prompt: str, api_key: str, model: str) -> str:
    """Call Groq's chat completions API with a short, non-retried timeout.

    Deliberately no retries: TNFR-4 requires Chronicle to degrade to the
    deterministic narrative quickly rather than stall the dashboard, and the
    caller already treats any exception here as "use the fallback".

    temperature=0 and JSON mode are both set because the caller parses this
    response as a strict JSON object and rejects anything that does not match
    the grounded shape exactly (_parse_live_explanation).
    """

    from groq import AsyncGroq

    timeout = float(
        os.getenv("CHRONICLE_LLM_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS)
    )
    reasoning_effort = os.getenv(
        "CHRONICLE_LLM_REASONING_EFFORT", DEFAULT_REASONING_EFFORT
    ).strip()
    extra = {"reasoning_effort": reasoning_effort} if reasoning_effort else {}

    async with AsyncGroq(
        api_key=api_key,
        timeout=timeout,
        max_retries=0,
    ) as client:
        completion = await client.chat.completions.create(
            model=model,
            max_tokens=MAX_OUTPUT_TOKENS,
            temperature=0,
            response_format={"type": "json_object"},
            messages=[{"role": "user", "content": prompt}],
            **extra,
        )

    choices = getattr(completion, "choices", None) or []
    if not choices:
        raise ValueError("Groq returned no choices")
    content = getattr(choices[0].message, "content", None)
    if not isinstance(content, str) or not content.strip():
        raise ValueError("Groq returned no text content")
    return content


def _parse_live_explanation(
    response_text: str,
    events: Sequence[SecurityEvent],
    incident_id: str,
    generated_at: str,
) -> dict[str, object]:
    try:
        response = json.loads(response_text)
    except json.JSONDecodeError as error:
        raise ValueError("Groq response was not valid JSON") from error

    expected_keys = {
        "summary",
        "affected_user",
        "affected_application",
        "suggested_remediation",
    }
    if not isinstance(response, dict) or set(response) != expected_keys:
        raise ValueError("Groq response did not match the expected shape")
    if not isinstance(response["summary"], str) or not response["summary"].strip():
        raise ValueError("Groq response did not contain a summary")

    known_users = {
        event.user_id for event in events if event.user_id is not None
    }
    known_applications = {
        event.application_id
        for event in events
        if event.application_id is not None
    }
    if response["affected_user"] not in known_users | {None}:
        raise ValueError("Groq response named an unknown user")
    if response["affected_application"] not in known_applications | {None}:
        raise ValueError("Groq response named an unknown application")

    remediations = response["suggested_remediation"]
    if not isinstance(remediations, list) or not all(
        isinstance(remediation, str) and remediation.strip()
        for remediation in remediations
    ):
        raise ValueError("Groq response contained invalid remediation data")

    grounded_remediations = {
        value
        for event in events
        for key, value in event.detail.items()
        if "remediation" in key.lower()
    }
    if any(remediation not in grounded_remediations for remediation in remediations):
        raise ValueError("Groq response contained an ungrounded remediation")

    return {
        "incident_id": incident_id,
        "related_event_ids": [event.event_id for event in events],
        "summary": response["summary"].strip(),
        "affected_user": response["affected_user"],
        "affected_application": response["affected_application"],
        "suggested_remediation": remediations,
        "generated_at": generated_at,
    }


@router.post("/explain")
async def explain_incident(request: ExplainRequest) -> JSONResponse:
    _validate_event_ids(request.event_ids)
    events = _fetch_events(request.event_ids)
    incident_id = str(uuid.uuid4())
    generated_at = _now()

    live_configuration = _live_configuration()
    if _is_fallback_forced() or live_configuration is None:
        explanation = build_fallback_explanation(
            events, incident_id, generated_at
        )
        return _explanation_response(explanation, events, "fallback")

    api_key, model = live_configuration
    try:
        prompt = build_chronicle_prompt(events)
        response_text = await _call_groq(prompt, api_key, model)
        explanation = _parse_live_explanation(
            response_text,
            events,
            incident_id,
            generated_at,
        )
    except Exception as error:
        logger.warning(
            "Chronicle live explanation failed; using fallback (%s)",
            type(error).__name__,
        )
        explanation = build_fallback_explanation(
            events, incident_id, generated_at
        )
        return _explanation_response(explanation, events, "fallback")

    return _explanation_response(explanation, events, "live")
