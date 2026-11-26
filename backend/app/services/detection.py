from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings, settings
from app.models.alert import Alert
from app.models.security_event import SecurityEvent


@dataclass(frozen=True)
class DetectionRule:
    rule_id: str
    severity: str
    description: str
    event_types: frozenset[str] = frozenset()
    threshold: int | None = None
    window_seconds: int | None = None


def configured_rules(config: Settings = settings) -> tuple[DetectionRule, ...]:
    return (
        DetectionRule(
            rule_id="repeated_failed_authentication",
            severity="high",
            description="Repeated failed authentication attempts detected.",
            event_types=frozenset(
                {"failed_login", "failed_authentication", "authentication_failed"}
            ),
            threshold=config.detection_failed_auth_threshold,
            window_seconds=config.detection_failed_auth_window_seconds,
        ),
        DetectionRule(
            rule_id="suspicious_login_activity",
            severity="high",
            description="A login event was marked as suspicious.",
            event_types=frozenset(
                {"suspicious_login", "unusual_login", "login_from_unusual_location"}
            ),
        ),
        DetectionRule(
            rule_id="repeated_access_denied",
            severity="medium",
            description="Repeated access-denied events detected.",
            event_types=frozenset({"access_denied", "authorization_denied"}),
            threshold=config.detection_access_denied_threshold,
            window_seconds=config.detection_access_denied_window_seconds,
        ),
        DetectionRule(
            rule_id="privilege_escalation_attempt",
            severity="critical",
            description="A privilege escalation attempt was reported.",
            event_types=frozenset(
                {"privilege_escalation", "privilege_escalation_attempt"}
            ),
        ),
        DetectionRule(
            rule_id="high_severity_event",
            severity="high",
            description="A high-severity security event was reported.",
        ),
    )


def _event_ingestion_time(event: SecurityEvent) -> datetime:
    ingested_at = event.created_at
    if ingested_at.tzinfo is None or ingested_at.utcoffset() is None:
        return ingested_at.replace(tzinfo=timezone.utc)
    return ingested_at.astimezone(timezone.utc)


def _rule_matches(
    db: Session,
    event: SecurityEvent,
    rule: DetectionRule,
    ingested_at: datetime,
) -> bool:
    if rule.event_types and event.event_type not in rule.event_types:
        return False
    if rule.threshold is not None and rule.window_seconds is not None:
        cutoff = ingested_at - timedelta(seconds=rule.window_seconds)
        recent_count = db.scalar(
            select(func.count(SecurityEvent.id)).where(
                SecurityEvent.tenant_id == event.tenant_id,
                SecurityEvent.event_type.in_(rule.event_types),
                SecurityEvent.created_at >= cutoff,
                SecurityEvent.created_at <= ingested_at,
            )
        )
        return recent_count >= rule.threshold
    if rule.rule_id == "high_severity_event":
        return event.severity in {"high", "critical"}
    return True


def alerts_for_event(
    db: Session,
    event: SecurityEvent,
    config: Settings = settings,
) -> list[Alert]:
    ingested_at = _event_ingestion_time(event)
    alerts = []
    for rule in configured_rules(config):
        if _rule_matches(db, event, rule, ingested_at):
            alert = Alert(
                tenant_id=event.tenant_id,
                event_id=event.id,
                rule_id=rule.rule_id,
                severity=(
                    event.severity
                    if rule.rule_id == "high_severity_event"
                    else rule.severity
                ),
                description=rule.description,
            )
            db.add(alert)
            alerts.append(alert)
    return alerts
