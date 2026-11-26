from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class IdentityCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    identity_type: Literal["human", "service"] = "human"
    role: Literal["admin", "analyst", "viewer"] = "viewer"


class IdentityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    email: EmailStr
    identity_type: Literal["human", "service"]
    status: Literal["active", "suspended", "revoked"]
    role: Literal["platform_admin", "admin", "analyst", "viewer"]
    created_at: datetime
    updated_at: datetime
