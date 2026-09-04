# SIMULATED DATA ONLY (PRD NFR-5 / §4.2). This is a fixed, hand-authored
# stand-in for a 100-account organization, entirely fictional — no real
# tenant, user, or application data is used or referenced anywhere here.
# Deterministic and static so the Radar demo score is reproducible run to
# run; do not replace with random generation.

from typing import TypedDict

ORGANIZATION_ID = "mock-org-01"


class Account(TypedDict):
    account_id: str
    mfa_method: str  # "passkey" | "sms" | "voice_call" | "totp" | "none"
    passkey_enrolled: bool
    passkey_enforced: bool
    weak_fallback_enabled: bool  # e.g. SMS/voice fallback can bypass an enrolled passkey
    device_code_enabled: bool
    is_admin: bool
    admin_monitored: bool  # relevant only when is_admin is True
    conditional_access_excluded: bool
    session_lifetime_days: int


class OAuthApp(TypedDict):
    application_id: str
    application_name: str
    publisher_verified: bool
    requested_scopes: list[str]
    is_org_allowlisted: bool
    offline_access_requested: bool
    excessive_permissions: bool


def _build_accounts() -> list[Account]:
    accounts: list[Account] = []
    for i in range(100):
        account_id = f"acct-{i:03d}"

        # ~18 accounts (indices 0-17) still have a phishable MFA method active.
        phishable_mfa = i < 18
        mfa_method = "sms" if i < 12 else "voice_call" if i < 18 else "passkey"

        # Passkeys are enrolled for most accounts but only *enforced* (no
        # fallback path) for a subset — indices 30-99 (70 accounts) have
        # passkeys enrolled and enforced; 0-29 do not enforce them.
        passkey_enrolled = i >= 5
        passkey_enforced = i >= 30

        # ~7 accounts (indices 18-24) have a weak fallback method that can
        # bypass an otherwise-enrolled passkey.
        weak_fallback_enabled = 18 <= i < 25

        # Device-code auth is unrestricted (no allowlist/registration gate)
        # for a broad swath of accounts — indices 0-39.
        device_code_enabled = i < 40

        # 6 admin accounts total (indices 90-95); 2 of them are unmonitored
        # break-glass style accounts (indices 90-91).
        is_admin = 90 <= i < 96
        admin_monitored = is_admin and i >= 92

        # Conditional Access exclusions apply to a small carve-out group
        # (indices 96-99), separate from the admin accounts.
        conditional_access_excluded = i >= 96

        # Session lifetime: most accounts sit at a normal 7-day session,
        # but a group of 15 (indices 40-54) has long-lived, effectively
        # unrevocable 90-day sessions.
        session_lifetime_days = 90 if 40 <= i < 55 else 7

        accounts.append(
            Account(
                account_id=account_id,
                mfa_method=mfa_method if phishable_mfa else "passkey",
                passkey_enrolled=passkey_enrolled,
                passkey_enforced=passkey_enforced,
                weak_fallback_enabled=weak_fallback_enabled,
                device_code_enabled=device_code_enabled,
                is_admin=is_admin,
                admin_monitored=admin_monitored,
                conditional_access_excluded=conditional_access_excluded,
                session_lifetime_days=session_lifetime_days,
            )
        )
    return accounts


def _build_oauth_apps() -> list[OAuthApp]:
    return [
        OAuthApp(
            application_id="app-001",
            application_name="QuickNotes Sync",
            publisher_verified=False,
            requested_scopes=["mail.read", "mail.send", "offline_access"],
            is_org_allowlisted=False,
            offline_access_requested=True,
            excessive_permissions=True,
        ),
        OAuthApp(
            application_id="app-002",
            application_name="TeamCalendar Connector",
            publisher_verified=False,
            requested_scopes=["calendar.readwrite"],
            is_org_allowlisted=False,
            offline_access_requested=False,
            excessive_permissions=False,
        ),
        OAuthApp(
            application_id="app-003",
            application_name="Internal Reporting Bot",
            publisher_verified=True,
            requested_scopes=["files.read"],
            is_org_allowlisted=True,
            offline_access_requested=False,
            excessive_permissions=False,
        ),
        OAuthApp(
            application_id="app-004",
            application_name="FileVault Backup Agent",
            publisher_verified=False,
            requested_scopes=["files.readwrite.all", "offline_access"],
            is_org_allowlisted=False,
            offline_access_requested=True,
            excessive_permissions=True,
        ),
    ]


def get_mock_org() -> dict:
    return {
        "organization_id": ORGANIZATION_ID,
        "accounts": _build_accounts(),
        "oauth_apps": _build_oauth_apps(),
    }
