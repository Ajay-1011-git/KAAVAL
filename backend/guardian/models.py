# Guardian data models — PRD FR-9/FR-10, build doc §B.2. Do not modify field
# names or types without a team decision.

from pydantic import BaseModel


class OAuthGrantRequest(BaseModel):
    application_id: str
    application_name: str
    publisher_verified: bool
    requested_scopes: list[str]
    redirect_uri: str
    offline_access_requested: bool
    is_org_allowlisted: bool


class DeviceCodeRequest(BaseModel):
    application_id: str
    device_registered: bool
    code_ttl_seconds: int
    is_allowlisted: bool
    is_sensitive_resource: bool
    admin_approved: bool
