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
