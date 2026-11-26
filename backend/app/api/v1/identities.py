import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.identity import Identity
from app.security.authentication import AuthenticatedIdentity
from app.security.policy import PolicyAction, PolicyResource, require_permission
from app.schemas.identity import IdentityCreate, IdentityResponse

router = APIRouter(prefix="/api/v1/identities", tags=["Identities"])
logger = logging.getLogger(__name__)


@router.get("", response_model=list[IdentityResponse])
def list_identities(
    identity: AuthenticatedIdentity = Depends(
        require_permission(PolicyAction.READ.value, PolicyResource.IDENTITY.value)
    ),
    db: Session = Depends(get_db),
) -> list[Identity]:
    statement = (
        select(Identity)
        .where(Identity.tenant_id == identity.tenant_id)
        .order_by(Identity.created_at)
    )
    return list(db.scalars(statement).all())


@router.post("", response_model=IdentityResponse, status_code=status.HTTP_201_CREATED)
def create_identity(
    payload: IdentityCreate,
    identity: AuthenticatedIdentity = Depends(
        require_permission(PolicyAction.MANAGE.value, PolicyResource.IDENTITY.value)
    ),
    db: Session = Depends(get_db),
) -> Identity:
    new_identity = Identity(
        tenant_id=identity.tenant_id,
        email=str(payload.email),
        identity_type=payload.identity_type,
        status="active",
        role=payload.role,
    )
    db.add(new_identity)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        logger.warning("Identity creation rejected due to an integrity constraint")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An identity with this email already exists in the tenant",
        ) from None
    db.refresh(new_identity)
    return new_identity
