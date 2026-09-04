from fastapi.testclient import TestClient

from backend.main import app

client = TestClient(app)


def test_get_report_known_org_returns_200_and_shape():
    resp = client.get("/radar/report", params={"org_id": "mock-org-01"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["organization_id"] == "mock-org-01"
    assert 0 <= body["exposure_score"] <= 100
    assert len(body["findings"]) > 0


def test_get_report_unknown_org_returns_404():
    resp = client.get("/radar/report", params={"org_id": "some-other-org"})
    assert resp.status_code == 404
