from backend.guardian.models import OAuthGrantRequest
from backend.guardian.oauth_policy import evaluate_oauth_grant


def test_unverified_broad_scopes_not_allowlisted_is_blocked():
    req = OAuthGrantRequest(
        application_id="app-004",
        application_name="FileVault Backup Agent",
        publisher_verified=False,
        requested_scopes=["files.readwrite.all", "offline_access"],
        redirect_uri="https://filevault-backup.example.com/oauth/callback",
        offline_access_requested=True,
        is_org_allowlisted=False,
    )
    decision, reason = evaluate_oauth_grant(req)
    assert decision == "block"
    assert reason == "unverified_publisher_with_offline_access_scope"


def test_verified_publisher_narrow_scopes_is_allowed():
    req = OAuthGrantRequest(
        application_id="app-003",
        application_name="Internal Reporting Bot",
        publisher_verified=True,
        requested_scopes=["files.read"],
        redirect_uri="https://reporting-bot.example.com/oauth/callback",
        offline_access_requested=False,
        is_org_allowlisted=True,
    )
    decision, reason = evaluate_oauth_grant(req)
    assert decision == "allow"
    assert reason == "publisher_verified"


def test_unverified_publisher_but_org_allowlisted_is_allowed():
    req = OAuthGrantRequest(
        application_id="app-002",
        application_name="TeamCalendar Connector",
        publisher_verified=False,
        requested_scopes=["calendar.readwrite"],
        redirect_uri="https://teamcalendar.example.com/oauth/callback",
        offline_access_requested=False,
        is_org_allowlisted=True,
    )
    decision, reason = evaluate_oauth_grant(req)
    assert decision == "allow"
    assert reason == "org_allowlisted"
