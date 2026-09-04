# Radar data models — TRD §6.3 / build doc §B.2. Do not modify field names or
# types without a team decision; radar/, guardian/, and the dashboard all
# depend on this shape being exact.

from pydantic import BaseModel
from typing import Literal


class RadarFinding(BaseModel):
    finding_id: str
    check: str
    severity: Literal["low", "medium", "high"]
    affected_count: int
    description: str
    remediation: str


class RadarReport(BaseModel):
    organization_id: str
    exposure_score: int  # 0-100
    exposure_label: Literal["Low", "Medium", "High"]
    generated_at: str
    findings: list[RadarFinding]
