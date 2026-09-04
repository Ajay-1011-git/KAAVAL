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
        # Added by KAAVAL_Amendment_Integration_Fixes.md FIX-6a, as a
        # whole-team amendment rather than a silent edit: the enum had a
        # blocked case with no allowed counterpart, so Guardian's device-code
        # allow path had to borrow the generic "request_allowed" and became
        # indistinguishable from a gateway request on the timeline.
        "device_code_allowed",
    ]
    session_id: Optional[str]
    user_id: Optional[str]
    application_id: Optional[str]  # relevant for Guardian events
    reason: str
    detail: dict  # small structured values only — never raw credentials or full tokens
    severity: Literal["info", "warning", "blocked"]


# --- Integration completion note -------------------------------------------
# Team Integration Plan §3.2 requires this file to carry all five frozen
# models. Stage 0 shipped only SignedRequestEnvelope and SecurityEvent, so
# RadarFinding/RadarReport were defined in backend/radar/models.py and
# IncidentExplanation was never modelled at all — exactly the "shadow copy"
# §7.2 forbids. The three below are copied verbatim from TRD §6.3/§6.4;
# backend/radar/models.py now re-exports these rather than redefining them.
# No existing field was changed.


class RadarFinding(BaseModel):
    finding_id: str
    check: str  # exact check name, e.g. "phishable_mfa_active"
    severity: Literal["low", "medium", "high"]
    affected_count: int
    description: str
    remediation: str


class RadarReport(BaseModel):
    organization_id: str  # always a clearly simulated id, e.g. "mock-org-01"
    exposure_score: int  # 0-100
    exposure_label: Literal["Low", "Medium", "High"]
    generated_at: str
    findings: list[RadarFinding]


class IncidentExplanation(BaseModel):
    incident_id: str
    related_event_ids: list[str]  # must reference real SecurityEvent.event_id values
    summary: str  # grounded only in the referenced events
    affected_user: Optional[str]
    affected_application: Optional[str]
    suggested_remediation: list[str]
    generated_at: str
