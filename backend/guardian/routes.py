# Guardian evaluation endpoints — build doc §C T-AD.8.

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter

from backend.contracts import SecurityEvent
from backend.events import write_event
from backend.guardian.device_code_policy import evaluate_device_code
from backend.guardian.models import DeviceCodeRequest, OAuthGrantRequest
from backend.guardian.oauth_policy import evaluate_oauth_grant

router = APIRouter(prefix="/guardian", tags=["guardian"])


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@router.post("/oauth/evaluate")
def oauth_evaluate(req: OAuthGrantRequest) -> dict:
    decision, reason = evaluate_oauth_grant(req)
    event_type = "oauth_grant_blocked" if decision == "block" else "oauth_grant_allowed"
    write_event(
        SecurityEvent(
            event_id=str(uuid.uuid4()),
            timestamp=_now(),
            event_type=event_type,
            session_id=None,
            user_id=None,
            application_id=req.application_id,
            reason=reason,
            detail={"application_name": req.application_name},
            severity="blocked" if decision == "block" else "info",
        )
    )
    return {"decision": decision, "reason": reason}


@router.post("/device-code/evaluate")
def device_code_evaluate(req: DeviceCodeRequest) -> dict:
    decision, reason = evaluate_device_code(req)
    # The contract gap flagged here is now closed: "device_code_allowed" was
    # added to SecurityEvent.event_type by amendment FIX-6a, so the allow path
    # no longer has to borrow the gateway's generic "request_allowed".
    event_type = "device_code_blocked" if decision == "block" else "device_code_allowed"
    write_event(
        SecurityEvent(
            event_id=str(uuid.uuid4()),
            timestamp=_now(),
            event_type=event_type,
            session_id=None,
            user_id=None,
            application_id=req.application_id,
            reason=reason,
            detail={"code_ttl_seconds": str(req.code_ttl_seconds)},
            severity="blocked" if decision == "block" else "info",
        )
    )
    return {"decision": decision, "reason": reason}
