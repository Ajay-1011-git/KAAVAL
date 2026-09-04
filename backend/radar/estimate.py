# backend/radar/estimate.py — operator-supplied exposure estimate.
#
# Radar normally scores a clearly-labelled simulated organisation, because
# live identity-provider integration is outside the MVP's scope (PRD §4.2).
# That leaves an administrator unable to get a number for their OWN
# organisation without a directory integration nobody has built yet.
#
# They don't need one. Every check in scoring.py reduces to
# (affected_count, population) — no check inspects WHICH account exhibits a
# weakness, only how many do. So a population synthesised to match a handful
# of operator-supplied counts scores identically to full per-account data.
# Not an approximation: the same score, the same severities, the same
# affected counts. test_estimate.py pins that equivalence against the mock
# org's real numbers.
#
# This is the mode PRD NFR-3 already describes — Radar's output is
# "estimates over a fixed checklist, not a certified audit" — so what changes
# here is only where the counts come from, never what the number means.
#
# The honesty constraint that makes this defensible: the counts must come
# from the operator, and the resulting report must never be mistakable for a
# measured tenant. Hence the fixed organization_id below, and validation that
# refuses impossible inputs rather than quietly scoring them.

from __future__ import annotations

from pydantic import BaseModel, Field, model_validator

# Deliberately not a tenant-shaped name. A report carrying this id is
# self-reported input, and the dashboard labels it as such.
ESTIMATE_ORGANIZATION_ID = "operator-estimate"

# Accounts whose session lifetime exceeds this are counted by
# check_long_lived_sessions. Mirrored here so the synthesised population
# lands on the correct side of that check's own threshold.
_LONG_LIVED_DAYS = 30
_SHORT_LIVED_DAYS = 1


class OrganizationCounts(BaseModel):
    """What an administrator can read off a couple of directory report screens.

    Every field is a count, not a rate, because that is the form the numbers
    actually arrive in and it keeps the input auditable — a reviewer can ask
    "where did 780 come from?" about any single figure.
    """

    total_accounts: int = Field(ge=1, description="Total user accounts in the organisation")

    phishable_mfa_accounts: int = Field(default=0, ge=0)
    passkey_enrolled_not_enforced: int = Field(default=0, ge=0)
    weak_fallback_accounts: int = Field(default=0, ge=0)
    device_code_enabled_accounts: int = Field(default=0, ge=0)
    admin_accounts: int = Field(default=0, ge=0)
    unmonitored_admin_accounts: int = Field(default=0, ge=0)
    conditional_access_excluded_accounts: int = Field(default=0, ge=0)
    long_lived_session_accounts: int = Field(default=0, ge=0)

    total_oauth_apps: int = Field(default=0, ge=0)
    unverified_unallowlisted_apps: int = Field(default=0, ge=0)
    excessive_permission_apps: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def _counts_must_be_possible(self) -> "OrganizationCounts":
        """Refuse impossible inputs instead of scoring them.

        A subset count larger than its population is not a small error — it
        would silently produce a severity ratio above 1.0 and a confidently
        wrong finding. Better to reject the input and say why.
        """
        account_subsets = {
            "phishable_mfa_accounts": self.phishable_mfa_accounts,
            "passkey_enrolled_not_enforced": self.passkey_enrolled_not_enforced,
            "weak_fallback_accounts": self.weak_fallback_accounts,
            "device_code_enabled_accounts": self.device_code_enabled_accounts,
            "admin_accounts": self.admin_accounts,
            "conditional_access_excluded_accounts": self.conditional_access_excluded_accounts,
            "long_lived_session_accounts": self.long_lived_session_accounts,
        }
        for name, value in account_subsets.items():
            if value > self.total_accounts:
                raise ValueError(
                    f"{name} ({value}) cannot exceed total_accounts ({self.total_accounts})"
                )

        if self.unmonitored_admin_accounts > self.admin_accounts:
            raise ValueError(
                f"unmonitored_admin_accounts ({self.unmonitored_admin_accounts}) cannot exceed "
                f"admin_accounts ({self.admin_accounts})"
            )

        app_subsets = {
            "unverified_unallowlisted_apps": self.unverified_unallowlisted_apps,
            "excessive_permission_apps": self.excessive_permission_apps,
        }
        for name, value in app_subsets.items():
            if value > self.total_oauth_apps:
                raise ValueError(
                    f"{name} ({value}) cannot exceed total_oauth_apps ({self.total_oauth_apps})"
                )

        return self


def build_org_from_counts(counts: OrganizationCounts) -> dict:
    """Synthesise a population matching the supplied counts.

    The account records are placeholders — the identifiers carry no meaning
    and no operator data. Only the per-check totals matter, and those are
    exactly what was supplied.
    """
    accounts = []
    for index in range(counts.total_accounts):
        is_admin = index < counts.admin_accounts
        accounts.append(
            {
                "account_id": f"estimate-account-{index}",
                # Any non-"passkey" value counts as phishable to the check.
                "mfa_method": "sms" if index < counts.phishable_mfa_accounts else "passkey",
                # The check requires enrolled AND not enforced, so enrolment is
                # what varies and enforcement stays false.
                "passkey_enrolled": index < counts.passkey_enrolled_not_enforced,
                "passkey_enforced": False,
                "weak_fallback_enabled": index < counts.weak_fallback_accounts,
                "device_code_enabled": index < counts.device_code_enabled_accounts,
                "is_admin": is_admin,
                # Only meaningful for admins; unmonitored admins are taken from
                # the front of the same range so the counts line up.
                "admin_monitored": not (is_admin and index < counts.unmonitored_admin_accounts),
                "conditional_access_excluded": index < counts.conditional_access_excluded_accounts,
                "session_lifetime_days": (
                    _LONG_LIVED_DAYS
                    if index < counts.long_lived_session_accounts
                    else _SHORT_LIVED_DAYS
                ),
            }
        )

    oauth_apps = []
    for index in range(counts.total_oauth_apps):
        unverified = index < counts.unverified_unallowlisted_apps
        oauth_apps.append(
            {
                "application_id": f"estimate-app-{index}",
                "application_name": f"Application {index + 1}",
                "publisher_verified": not unverified,
                "requested_scopes": [],
                "is_org_allowlisted": False,
                "offline_access_requested": False,
                "excessive_permissions": index < counts.excessive_permission_apps,
            }
        )

    return {
        "organization_id": ESTIMATE_ORGANIZATION_ID,
        "accounts": accounts,
        "oauth_apps": oauth_apps,
    }
