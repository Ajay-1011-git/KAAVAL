# Device-code policy — PRD FR-9, build doc §C T-AD.7. Default-block; every
# allow path must satisfy all stated conditions (GROUND TRUTH — do not soften
# the default-deny direction).

from typing import Literal

from backend.guardian.models import DeviceCodeRequest

# "Short-lived" per PRD FR-9: a device code must expire quickly to limit the
# window a phished code stays usable. 300s (5 min) matches typical
# short-lived device-code guidance; single-use-ness is inherent to the
# device-code flow itself, not a field this model tracks separately.
MAX_DEVICE_CODE_TTL_SECONDS = 300


def evaluate_device_code(req: DeviceCodeRequest) -> tuple[Literal["allow", "block"], str]:
    if not req.is_allowlisted:
        return "block", "application_not_allowlisted"

    if not req.device_registered:
        return "block", "device_not_registered"

    if req.code_ttl_seconds > MAX_DEVICE_CODE_TTL_SECONDS:
        return "block", "code_not_short_lived"

    if req.is_sensitive_resource and not req.admin_approved:
        return "block", "sensitive_resource_without_admin_approval"

    return "allow", "policy_conditions_satisfied"
