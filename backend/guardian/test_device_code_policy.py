from backend.guardian.device_code_policy import evaluate_device_code
from backend.guardian.models import DeviceCodeRequest


def test_no_exception_conditions_met_is_blocked():
    req = DeviceCodeRequest(
        application_id="app-legacy-cli",
        device_registered=False,
        code_ttl_seconds=900,
        is_allowlisted=False,
        is_sensitive_resource=True,
        admin_approved=False,
    )
    decision, reason = evaluate_device_code(req)
    assert decision == "block"
    assert reason == "application_not_allowlisted"


def test_all_conditions_met_non_sensitive_is_allowed():
    req = DeviceCodeRequest(
        application_id="app-approved-cli",
        device_registered=True,
        code_ttl_seconds=120,
        is_allowlisted=True,
        is_sensitive_resource=False,
        admin_approved=False,
    )
    decision, reason = evaluate_device_code(req)
    assert decision == "allow"
    assert reason == "policy_conditions_satisfied"


def test_all_conditions_met_but_sensitive_without_admin_approval_is_blocked():
    req = DeviceCodeRequest(
        application_id="app-approved-cli",
        device_registered=True,
        code_ttl_seconds=120,
        is_allowlisted=True,
        is_sensitive_resource=True,
        admin_approved=False,
    )
    decision, reason = evaluate_device_code(req)
    assert decision == "block"
    assert reason == "sensitive_resource_without_admin_approval"


def test_an_allowed_device_code_writes_a_device_code_allowed_event():
    """FIX-6a VERIFY: the allow path now has its own event_type.

    Before the amendment this borrowed the gateway's generic
    "request_allowed" and was indistinguishable from an ordinary request on
    the dashboard timeline.
    """
    import os
    import tempfile
    from unittest.mock import patch

    from fastapi.testclient import TestClient

    from backend.db import get_connection, init_db
    from backend.main import app

    temp_db = os.path.join(
        tempfile.mkdtemp(prefix="kaaval_fix6a_"), "fix6a.db"
    ).replace("\\", "/")

    with patch.dict(os.environ, {"DATABASE_URL": f"sqlite:///{temp_db}"}, clear=False):
        init_db()
        client = TestClient(app)
        response = client.post(
            "/guardian/device-code/evaluate",
            json={
                "application_id": "app-trusted-1",
                "device_registered": True,
                "code_ttl_seconds": 60,
                "is_allowlisted": True,
                "is_sensitive_resource": False,
                "admin_approved": True,
            },
        )
        assert response.status_code == 200, response.text
        assert response.json()["decision"] == "allow", response.json()

        conn = get_connection()
        try:
            rows = conn.execute(
                "SELECT event_type, application_id FROM events"
                " WHERE application_id = 'app-trusted-1'"
            ).fetchall()
        finally:
            conn.close()

    assert [dict(r) for r in rows] == [
        {"event_type": "device_code_allowed", "application_id": "app-trusted-1"}
    ]
    print("DEVICE-CODE ALLOW EVENT:", [dict(r) for r in rows])
