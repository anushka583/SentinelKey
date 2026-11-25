from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.audit_event import AuditEvent
from app.schemas.audit_event import AuditEventResponse

router = APIRouter(prefix="/api/v1/audit-events", tags=["Audit Events"])


@router.get("", response_model=list[AuditEventResponse])
def list_audit_events(db: Session = Depends(get_db)) -> list[AuditEvent]:
    return list(db.scalars(select(AuditEvent).order_by(AuditEvent.created_at)).all())
