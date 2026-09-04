# Radar data models — TRD §6.3 / build doc §B.2.
#
# These models now live in backend/contracts.py, the single source of truth
# required by Team Integration Plan §3.2/§7.2. This module re-exports them so
# every existing `from backend.radar.models import RadarReport` import keeps
# working while there is only one definition of the shape.

from backend.contracts import RadarFinding, RadarReport

__all__ = ["RadarFinding", "RadarReport"]
