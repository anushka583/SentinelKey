from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class AuditEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    actor_identity_id: str | None
    action: str
    resource_type: str
    resource_id: str
    outcome: str
    details: dict[str, Any]
    created_at: datetime
