from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class SecurityEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    event_type: str
    severity: str
    source: str
    description: str
    payload: dict[str, Any]
    created_at: datetime
