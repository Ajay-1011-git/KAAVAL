# Radar report endpoint — build doc §C T-AD.4.

from fastapi import APIRouter, HTTPException

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
