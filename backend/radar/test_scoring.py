from backend.radar.mock_org import get_mock_org
from backend.radar.scoring import CHECKS, generate_radar_report


def test_every_check_that_fires_names_itself():
    org = get_mock_org()
    for check in CHECKS:
        finding = check(org)
        if finding is not None:
            assert finding.check == check.__name__.removeprefix("check_")


def test_report_is_reproducible_in_shape():
    org = get_mock_org()
    report = generate_radar_report(org)
    assert report.organization_id == "mock-org-01"
    assert 0 <= report.exposure_score <= 100
    assert report.exposure_label in ("Low", "Medium", "High")
    assert len(report.findings) > 0


def test_no_findings_yields_zero_score_and_low_label():
    empty_org = {"organization_id": "mock-org-01", "accounts": [], "oauth_apps": []}
    report = generate_radar_report(empty_org)
    assert report.exposure_score == 0
    assert report.exposure_label == "Low"
    assert report.findings == []
