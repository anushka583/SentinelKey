from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


AlertStatus = Literal["New", "Acknowledged", "Resolved"]
AlertSeverity = Literal["critical", "high", "medium", "low", "informational"]


class AlertUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: AlertStatus


class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    event_id: str
    rule_id: str
    severity: AlertSeverity
    description: str = Field(max_length=500)
    status: AlertStatus
    created_at: datetime
    updated_at: datetime

    @field_validator("created_at", "updated_at", mode="before")
    @classmethod
    def mark_sqlite_timestamps_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
