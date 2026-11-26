from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.alert import Alert
from app.security.authentication import AuthenticatedIdentity
from app.security.policy import PolicyAction, PolicyResource, require_permission
from app.schemas.alert import AlertResponse, AlertStatus, AlertUpdate

router = APIRouter(prefix="/api/v1/alerts", tags=["Alerts"])


def _tenant_alert(
    db: Session,
    alert_id: UUID,
    tenant_id: str,
) -> Alert:
    alert = db.scalar(
        select(Alert).where(
            Alert.id == str(alert_id),
            Alert.tenant_id == tenant_id,
        )
    )
    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )
    return alert


@router.get("", response_model=list[AlertResponse])
def list_alerts(
    status_filter: AlertStatus | None = Query(default=None, alias="status"),
    identity: AuthenticatedIdentity = Depends(
        require_permission(PolicyAction.READ.value, PolicyResource.ALERT.value)
    ),
    db: Session = Depends(get_db),
) -> list[Alert]:
    statement = select(Alert).where(Alert.tenant_id == identity.tenant_id)
    if status_filter is not None:
        statement = statement.where(Alert.status == status_filter)
    return list(db.scalars(statement.order_by(Alert.created_at.desc())).all())


@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert(
    alert_id: UUID,
    identity: AuthenticatedIdentity = Depends(
        require_permission(PolicyAction.READ.value, PolicyResource.ALERT.value)
    ),
    db: Session = Depends(get_db),
) -> Alert:
    return _tenant_alert(db, alert_id, identity.tenant_id)


@router.patch("/{alert_id}", response_model=AlertResponse)
def update_alert(
    alert_id: UUID,
    payload: AlertUpdate,
    identity: AuthenticatedIdentity = Depends(
        require_permission(PolicyAction.UPDATE.value, PolicyResource.ALERT.value)
    ),
    db: Session = Depends(get_db),
) -> Alert:
    alert = _tenant_alert(db, alert_id, identity.tenant_id)
    alert.status = payload.status
    db.commit()
    db.refresh(alert)
    return alert
