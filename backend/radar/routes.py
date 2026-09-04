# Radar report endpoint — build doc §C T-AD.4.

from fastapi import APIRouter, HTTPException

from backend.radar.estimate import OrganizationCounts, build_org_from_counts
from backend.radar.mock_org import ORGANIZATION_ID, get_mock_org
from backend.radar.models import RadarReport
from backend.radar.scoring import generate_radar_report

router = APIRouter(prefix="/radar", tags=["radar"])


@router.get("/report", response_model=RadarReport)
def get_radar_report(org_id: str) -> RadarReport:
    # There is no live-tenant mode in this MVP — any org_id other than the
    # known simulated one is a 404, not a silently-accepted arbitrary id.
    if org_id != ORGANIZATION_ID:
        raise HTTPException(status_code=404, detail=f"Unknown organization_id: {org_id}")

    org = get_mock_org()
    return generate_radar_report(org)


@router.post("/estimate", response_model=RadarReport)
def estimate_radar_report(counts: OrganizationCounts) -> RadarReport:
    """Score an organisation from operator-supplied counts.

    Same nine checks, same formula, same report shape as /report — the only
    difference is where the numbers came from. Radar's checks consume only
    (affected_count, population), so counts alone reproduce the score that
    full per-account data would produce (test_estimate.py pins this).

    The result carries ESTIMATE_ORGANIZATION_ID rather than a tenant-shaped
    name, because it is self-reported input and must not be mistakable for a
    measured directory (PRD NFR-3: Radar's scores are estimates over a fixed
    checklist, not a certified audit).

    Impossible counts are a 422 from the model's own validation rather than a
    confidently wrong finding.
    """
    return generate_radar_report(build_org_from_counts(counts))
