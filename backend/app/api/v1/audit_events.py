from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.audit_event import AuditEvent
from app.security.authentication import AuthenticatedIdentity
from app.security.policy import PolicyAction, PolicyResource, require_permission
from app.schemas.audit_event import AuditEventResponse

router = APIRouter(prefix="/api/v1/audit-events", tags=["Audit Events"])


@router.get("", response_model=list[AuditEventResponse])
def list_audit_events(
    identity: AuthenticatedIdentity = Depends(
        require_permission(PolicyAction.READ.value, PolicyResource.AUDIT_EVENT.value)
    ),
    db: Session = Depends(get_db),
) -> list[AuditEvent]:
    statement = (
        select(AuditEvent)
        .where(AuditEvent.tenant_id == identity.tenant_id)
        .order_by(AuditEvent.created_at)
    )
    return list(db.scalars(statement).all())
