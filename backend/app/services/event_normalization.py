from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from app.schemas.security_event import SecurityEventCreate


@dataclass(frozen=True)
class NormalizedSecurityEvent:
    event_type: str
    severity: str
    source: str
    description: str
    timestamp: datetime
    metadata: dict[str, Any]
    origin: str


def normalize_event(payload: SecurityEventCreate) -> NormalizedSecurityEvent:
    timestamp = payload.timestamp or datetime.now(timezone.utc)
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("Event timestamp must include a timezone")
    return NormalizedSecurityEvent(
        event_type=payload.event_type,
        severity=payload.severity,
        source=payload.source,
        description=payload.description,
        timestamp=timestamp.astimezone(timezone.utc),
        metadata=payload.metadata,
        origin=payload.origin,
    )
