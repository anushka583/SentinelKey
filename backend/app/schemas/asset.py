from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AssetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    hostname: str
    asset_type: str
    criticality: str
    created_at: datetime
    updated_at: datetime
