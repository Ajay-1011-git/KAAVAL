# backend/radar/test_estimate.py
#
# Radar's checks only ever consume (affected_count, population) — no check
# looks at WHICH account exhibits a weakness, only how many do. So an operator
# who knows a handful of counts about their own organisation can be scored by
# the identical engine, with an identical result, without any directory
# integration. That is what these tests pin: same numbers in, same score out.
#
# PRD NFR-3 already frames Radar's output this way — "estimates over a fixed
# checklist, not a certified audit" — so this is the mode the document
# describes, not a shortcut around it. The numbers must come from the operator
# and the report must say so, which is why the organization_id is fixed to
# a value that cannot be mistaken for a measured tenant.

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from backend.radar.estimate import (
    ESTIMATE_ORGANIZATION_ID,
    OrganizationCounts,
    build_org_from_counts,
)
from backend.radar.mock_org import get_mock_org
from backend.radar.routes import router
from backend.radar.scoring import generate_radar_report

def _app_with_router() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app


client = TestClient(_app_with_router())


# The mock org's real counts, so we can prove counts-only scoring matches
# full per-account scoring exactly.
MOCK_COUNTS = OrganizationCounts(
    total_accounts=100,
    phishable_mfa_accounts=18,
    passkey_enrolled_not_enforced=25,
    weak_fallback_accounts=7,
    device_code_enabled_accounts=40,
    admin_accounts=6,
    unmonitored_admin_accounts=2,
    conditional_access_excluded_accounts=4,
    long_lived_session_accounts=15,
    total_oauth_apps=8,
    unverified_unallowlisted_apps=3,
    excessive_permission_apps=2,
)


def test_counts_alone_reproduce_the_full_per_account_score():
    """The whole premise: no directory integration needed to get the real number."""
    from_full_data = generate_radar_report(get_mock_org())
    from_counts = generate_radar_report(build_org_from_counts(MOCK_COUNTS))

    assert from_counts.exposure_score == from_full_data.exposure_score
    assert from_counts.exposure_label == from_full_data.exposure_label
    assert [(f.check, f.severity, f.affected_count) for f in from_counts.findings] == [
        (f.check, f.severity, f.affected_count) for f in from_full_data.findings
    ]


def test_the_report_is_labelled_as_an_operator_estimate():
    """It must be impossible to mistake this for a measured tenant."""
    report = generate_radar_report(build_org_from_counts(MOCK_COUNTS))

    assert report.organization_id == ESTIMATE_ORGANIZATION_ID
    assert "estimate" in ESTIMATE_ORGANIZATION_ID


def test_a_clean_organisation_scores_zero():
    counts = OrganizationCounts(total_accounts=500)
    report = generate_radar_report(build_org_from_counts(counts))

    assert report.exposure_score == 0
    assert report.exposure_label == "Low"
    assert report.findings == []


def test_fixing_something_lowers_the_score():
    worse = generate_radar_report(build_org_from_counts(MOCK_COUNTS))
    better = generate_radar_report(
        build_org_from_counts(MOCK_COUNTS.model_copy(update={"phishable_mfa_accounts": 0}))
    )

    assert better.exposure_score < worse.exposure_score


# --- input validation: garbage in must not silently produce a score ----

def test_a_count_cannot_exceed_the_population():
    with pytest.raises(ValidationError):
        OrganizationCounts(total_accounts=10, phishable_mfa_accounts=11)


def test_unmonitored_admins_cannot_exceed_admins():
    with pytest.raises(ValidationError):
        OrganizationCounts(total_accounts=100, admin_accounts=3, unmonitored_admin_accounts=4)


def test_an_oauth_count_cannot_exceed_the_app_total():
    with pytest.raises(ValidationError):
        OrganizationCounts(total_accounts=10, total_oauth_apps=2, excessive_permission_apps=3)


def test_counts_cannot_be_negative():
    with pytest.raises(ValidationError):
        OrganizationCounts(total_accounts=10, phishable_mfa_accounts=-1)


def test_an_organisation_needs_at_least_one_account():
    with pytest.raises(ValidationError):
        OrganizationCounts(total_accounts=0)


def test_zero_oauth_apps_is_allowed_and_fires_no_app_findings():
    counts = OrganizationCounts(total_accounts=50, total_oauth_apps=0, phishable_mfa_accounts=10)
    report = generate_radar_report(build_org_from_counts(counts))

    app_checks = {"unknown_oauth_apps", "excessive_app_permissions"}
    assert not app_checks.intersection({f.check for f in report.findings})


# --- the endpoint ------------------------------------------------------

def test_the_endpoint_scores_operator_supplied_counts():
    response = client.post("/radar/estimate", json=MOCK_COUNTS.model_dump())

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["exposure_score"] == 76
    assert body["organization_id"] == ESTIMATE_ORGANIZATION_ID
    assert len(body["findings"]) == 9


def test_the_endpoint_rejects_impossible_counts_rather_than_scoring_them():
    response = client.post(
        "/radar/estimate", json={"total_accounts": 10, "phishable_mfa_accounts": 999}
    )

    assert response.status_code == 422


def test_the_mock_endpoint_is_untouched_by_this_addition():
    response = client.get("/radar/report?org_id=mock-org-01")

    assert response.status_code == 200
    assert response.json()["organization_id"] == "mock-org-01"
