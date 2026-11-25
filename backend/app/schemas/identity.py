from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class IdentityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    email: EmailStr
    identity_type: Literal["human", "service"]
    status: Literal["active", "suspended", "revoked"]
    created_at: datetime
    updated_at: datetime
