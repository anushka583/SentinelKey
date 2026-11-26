import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.config import settings


class SecurityEventCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_type: str = Field(min_length=1, max_length=100)
    severity: str
    source: str = Field(min_length=1, max_length=255)
    description: str = Field(min_length=1, max_length=5_000)
    timestamp: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    origin: Literal["manual", "simulated", "integration"] = "manual"

    @model_validator(mode="before")
    @classmethod
    def support_legacy_payload(cls, value):
        if not isinstance(value, dict) or "payload" not in value:
            return value
        data = dict(value)
        payload = data.pop("payload")
        if "metadata" in data:
            raise ValueError("Provide metadata or payload, not both")
        data["metadata"] = payload
        return data

    @field_validator("event_type")
    @classmethod
    def normalize_event_type(cls, value: str) -> str:
        normalized = re.sub(r"[\s-]+", "_", value.strip().casefold())
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,99}", normalized):
            raise ValueError("Invalid event type")
        return normalized

    @field_validator("severity")
    @classmethod
    def normalize_severity(cls, value: str) -> str:
        normalized = value.strip().casefold()
        if normalized == "info":
            normalized = "informational"
        if normalized not in {
            "critical",
            "high",
            "medium",
            "low",
            "informational",
        }:
            raise ValueError("Unsupported severity")
        return normalized

    @field_validator("source", "description")
    @classmethod
    def require_nonblank_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Field cannot be blank")
        return normalized

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return value
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Timestamp must include a timezone")
        if value > datetime.now(timezone.utc) + timedelta(minutes=5):
            raise ValueError("Timestamp cannot be more than five minutes in the future")
        return value.astimezone(timezone.utc)

    @field_validator("origin")
    @classmethod
    def validate_origin(cls, value: str) -> str:
        normalized = value.strip().casefold()
        if normalized not in {"manual", "simulated", "integration"}:
            raise ValueError("Unsupported event origin")
        return normalized

    @field_validator("metadata")
    @classmethod
    def validate_metadata_size(cls, value: dict[str, Any]) -> dict[str, Any]:
        try:
            encoded = json.dumps(value, separators=(",", ":"), allow_nan=False)
        except (RecursionError, TypeError, ValueError) as error:
            raise ValueError("Metadata must contain JSON-compatible values") from error
        if len(encoded.encode("utf-8")) > settings.event_metadata_max_bytes:
            raise ValueError("Metadata exceeds the configured size limit")
        return value


class SecurityEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    event_type: str
    severity: str
    source: str
    description: str
    payload: dict[str, Any]
    metadata: dict[str, Any] = Field(validation_alias="payload")
    timestamp: datetime = Field(validation_alias="event_timestamp")
    origin: str
    created_at: datetime

    @field_validator("timestamp", mode="before")
    @classmethod
    def mark_sqlite_timestamps_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


class SecurityEventTimeBucket(BaseModel):
    date: str
    count: int


class SecurityMonitoringSummary(BaseModel):
    total_events: int
    critical_events: int
    high_severity_events: int
    events_by_source: dict[str, int]
    new_alerts: int
    acknowledged_alerts: int
    resolved_alerts: int
    events_over_time: list[SecurityEventTimeBucket]
