# backend/radar/test_scoring_normalisation.py
#
# The exposure score used to be min(100, sum(weights)). Against the mock org
# the weights sum to 205, so the score pinned at 100 and 105 points of real
# findings were invisible: an administrator could remediate three high-severity
# findings and watch the headline number not move at all, which makes the score
# useless as a progress signal and indefensible to a judge asking "so what
# happens if we fix this one?".
#
# The score is now normalised against the worst case the checklist can express,
# so it is strictly monotonic in the findings and never saturates.

import pytest

from backend.radar.mock_org import get_mock_org
from backend.radar.scoring import (
    CHECKS,
    MAX_RAW_SCORE,
    _SEVERITY_WEIGHTS,
    generate_radar_report,
)

EMPTY_ORG = {"organization_id": "mock-org-01", "accounts": [], "oauth_apps": []}


def test_max_raw_score_is_every_check_at_its_heaviest():
    assert MAX_RAW_SCORE == len(CHECKS) * _SEVERITY_WEIGHTS["high"]


def test_the_mock_org_no_longer_pins_at_100():
    report = generate_radar_report(get_mock_org())

    raw = sum(_SEVERITY_WEIGHTS[f.severity] for f in report.findings)
    assert raw > 100, "precondition: this org's raw weight really does exceed 100"
    assert report.exposure_score < 100, (
        "a score of exactly 100 for a non-worst-case org is the saturation bug"
    )
    assert report.exposure_score == round(100 * raw / MAX_RAW_SCORE)


def test_score_stays_inside_the_contract_range():
    report = generate_radar_report(get_mock_org())
    assert 0 <= report.exposure_score <= 100


def test_no_findings_is_still_zero_and_low():
    report = generate_radar_report(EMPTY_ORG)
    assert report.exposure_score == 0
    assert report.exposure_label == "Low"


def test_removing_a_finding_actually_lowers_the_score():
    """The property the old formula destroyed: remediation must show up.

    Every account is given a passkey as its MFA method, which clears the
    phishable-MFA finding. The score must fall, not sit at 100.
    """
    org = get_mock_org()
    before = generate_radar_report(org)

    remediated = {
        **org,
        "accounts": [{**a, "mfa_method": "passkey"} for a in org["accounts"]],
    }
    after = generate_radar_report(remediated)

    assert len(after.findings) < len(before.findings)
    assert after.exposure_score < before.exposure_score


def test_the_worst_expressible_case_scores_100():
    """Normalisation must still be able to reach the top of the range."""
    weights = [_SEVERITY_WEIGHTS["high"]] * len(CHECKS)
    assert round(100 * sum(weights) / MAX_RAW_SCORE) == 100


@pytest.mark.parametrize(
    "score,expected",
    [(0, "Low"), (39, "Low"), (40, "Medium"), (69, "Medium"), (70, "High"), (100, "High")],
)
def test_label_thresholds_are_unchanged(score, expected):
    from backend.radar.scoring import _exposure_label

    assert _exposure_label(score) == expected
