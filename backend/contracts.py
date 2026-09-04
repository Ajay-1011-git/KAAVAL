# MINIMAL STAND-IN for Rohith's Stage 0 scaffold (Team Integration Plan §3).
# Frozen per TRD §6.1/§6.2. Do not modify field names, types, or the event_type
# literal without a synchronous team decision (Team Integration Plan §2/§7).

from pydantic import BaseModel
from typing import Optional, Literal


class SignedRequestEnvelope(BaseModel):
    session_id: str
    method: str
    origin: str
    path: str
    body_hash: str
    nonce: str
    sequence: int
    timestamp: str
    signature: str


class SecurityEvent(BaseModel):
    event_id: str
    timestamp: str
    event_type: Literal[
        "session_bound",
        "replay_attempted",
        "proof_absent",
        "signature_invalid",
        "request_blocked",
        "request_allowed",
        "oauth_grant_blocked",
        "oauth_grant_allowed",
        "device_code_blocked",
    ]
    session_id: Optional[str]
    user_id: Optional[str]
    application_id: Optional[str]
    reason: str
    detail: dict
    severity: Literal["info", "warning", "blocked"]
