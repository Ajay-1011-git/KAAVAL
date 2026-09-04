# OAuth-consent policy — PRD FR-10, build doc §C T-AD.6. Pure if/else policy;
# no numeric risk score anywhere in this module (GROUND TRUTH).

from typing import Literal

from backend.guardian.models import OAuthGrantRequest

# Scopes considered high-risk on their own (broad data access). Offline
# access is evaluated separately below since it has its own named reason.
HIGH_RISK_SCOPES = {
    "mail.read",
    "mail.send",
    "files.readwrite.all",
    "calendar.readwrite.all",
    "directory.readwrite.all",
}


def evaluate_oauth_grant(req: OAuthGrantRequest) -> tuple[Literal["allow", "block"], str]:
    has_high_risk_scope = bool(set(req.requested_scopes) & HIGH_RISK_SCOPES)
    has_offline_access = req.offline_access_requested
    requests_dangerous_access = has_high_risk_scope or has_offline_access

    if req.publisher_verified:
        return "allow", "publisher_verified"

    if req.is_org_allowlisted:
        return "allow", "org_allowlisted"

    if not requests_dangerous_access:
        return "allow", "no_high_risk_scope_requested"

    # Unverified publisher, not allowlisted, and requesting dangerous access:
    # block, naming exactly which dangerous-access condition triggered it.
    if has_offline_access:
        return "block", "unverified_publisher_with_offline_access_scope"
    return "block", "unverified_publisher_with_high_risk_scope"
