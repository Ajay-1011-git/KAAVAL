# backend/contracts.py
#
# FROZEN CONTRACT — copied verbatim from KAAVAL_TRD.md §6.1 and §6.2.
# Every module imports these types. Do not redefine SignedRequestEnvelope
# or SecurityEvent anywhere else in the backend. Do not modify this file
# after Stage 0 without a synchronous, whole-team decision (see
# KAAVAL_Team_Integration_Plan.md §2 and §7).

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
    application_id: Optional[str]  # relevant for Guardian events
    reason: str
    detail: dict  # small structured values only — never raw credentials or full tokens
    severity: Literal["info", "warning", "blocked"]
