from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.security_event import SecurityEvent
from app.schemas.security_event import SecurityEventResponse

router = APIRouter(prefix="/api/v1/security-events", tags=["Security Events"])


@router.get("", response_model=list[SecurityEventResponse])
def list_security_events(db: Session = Depends(get_db)) -> list[SecurityEvent]:
    return list(db.scalars(select(SecurityEvent).order_by(SecurityEvent.created_at)).all())
