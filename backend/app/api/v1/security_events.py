import logging
from datetime import datetime, time, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.alert import Alert
from app.models.security_event import SecurityEvent
from app.security.authentication import AuthenticatedIdentity
from app.security.policy import PolicyAction, PolicyResource, require_permission
from app.schemas.security_event import (
    SecurityEventCreate,
    SecurityEventResponse,
    SecurityEventTimeBucket,
    SecurityMonitoringSummary,
)
from app.services.detection import alerts_for_event
from app.services.event_normalization import normalize_event

router = APIRouter(prefix="/api/v1/security-events", tags=["Security Events"])
logger = logging.getLogger(__name__)


@router.get("", response_model=list[SecurityEventResponse])
def list_security_events(
    identity: AuthenticatedIdentity = Depends(
        require_permission(
            PolicyAction.READ.value,
            PolicyResource.SECURITY_EVENT.value,
        )
    ),
    db: Session = Depends(get_db),
) -> list[SecurityEvent]:
    statement = (
        select(SecurityEvent)
        .where(SecurityEvent.tenant_id == identity.tenant_id)
        .order_by(SecurityEvent.created_at)
    )
    return list(db.scalars(statement).all())


@router.post("", response_model=SecurityEventResponse, status_code=status.HTTP_201_CREATED)
def ingest_security_event(
    payload: SecurityEventCreate,
    identity: AuthenticatedIdentity = Depends(
        require_permission(
            PolicyAction.INGEST.value,
            PolicyResource.SECURITY_EVENT.value,
        )
    ),
    db: Session = Depends(get_db),
) -> SecurityEvent:
    normalized = normalize_event(payload)
    event = SecurityEvent(
        tenant_id=identity.tenant_id,
        event_type=normalized.event_type,
        severity=normalized.severity,
        source=normalized.source,
        description=normalized.description,
        payload=normalized.metadata,
        event_timestamp=normalized.timestamp,
        origin=normalized.origin,
    )
    db.add(event)
    db.flush()
    generated_alerts = alerts_for_event(db, event)
    db.commit()
    db.refresh(event)
    logger.info("Security event ingested; generated_alerts=%d", len(generated_alerts))
    return event


@router.get("/summary", response_model=SecurityMonitoringSummary)
def security_monitoring_summary(
    days: int = Query(default=30, ge=1, le=90),
    identity: AuthenticatedIdentity = Depends(
        require_permission(
            PolicyAction.READ.value,
            PolicyResource.SECURITY_EVENT.value,
        )
    ),
    db: Session = Depends(get_db),
) -> SecurityMonitoringSummary:
    tenant_filter = SecurityEvent.tenant_id == identity.tenant_id
    counts = db.execute(
        select(
            func.count(SecurityEvent.id),
            func.coalesce(
                func.sum(
                    case((func.lower(SecurityEvent.severity) == "critical", 1), else_=0)
                ),
                0,
            ),
            func.coalesce(
                func.sum(
                    case((func.lower(SecurityEvent.severity) == "high", 1), else_=0)
                ),
                0,
            ),
        ).where(tenant_filter)
    ).one()
    source_counts = db.execute(
        select(SecurityEvent.source, func.count(SecurityEvent.id))
        .where(tenant_filter)
        .group_by(SecurityEvent.source)
    ).all()
    alert_counts = db.execute(
        select(Alert.status, func.count(Alert.id))
        .where(Alert.tenant_id == identity.tenant_id)
        .group_by(Alert.status)
    ).all()

    today = datetime.now(timezone.utc).date()
    first_day = today - timedelta(days=days - 1)
    start = datetime.combine(first_day, time.min, tzinfo=timezone.utc)
    end = datetime.combine(today + timedelta(days=1), time.min, tzinfo=timezone.utc)
    daily_counts = db.execute(
        select(func.date(SecurityEvent.event_timestamp), func.count(SecurityEvent.id))
        .where(
            tenant_filter,
            SecurityEvent.event_timestamp >= start,
            SecurityEvent.event_timestamp < end,
        )
        .group_by(func.date(SecurityEvent.event_timestamp))
    ).all()
    counts_by_date = {str(event_date): count for event_date, count in daily_counts}
    events_over_time = [
        SecurityEventTimeBucket(
            date=(first_day + timedelta(days=offset)).isoformat(),
            count=counts_by_date.get(
                (first_day + timedelta(days=offset)).isoformat(), 0
            ),
        )
        for offset in range(days)
    ]
    alerts_by_status = dict(alert_counts)
    return SecurityMonitoringSummary(
        total_events=counts[0],
        critical_events=counts[1],
        high_severity_events=counts[2],
        events_by_source=dict(source_counts),
        new_alerts=alerts_by_status.get("New", 0),
        acknowledged_alerts=alerts_by_status.get("Acknowledged", 0),
        resolved_alerts=alerts_by_status.get("Resolved", 0),
        events_over_time=events_over_time,
    )
