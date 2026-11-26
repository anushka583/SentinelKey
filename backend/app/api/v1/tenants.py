import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.tenant import Tenant
from app.security.authentication import AuthenticatedIdentity
from app.security.policy import (
    PolicyAction,
    PolicyResource,
    require_permission,
)
from app.schemas.tenant import TenantCreate, TenantResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/tenants", tags=["Tenants"])


@router.get("", response_model=list[TenantResponse])
def list_tenants(
    identity: AuthenticatedIdentity = Depends(
        require_permission(PolicyAction.READ.value, PolicyResource.TENANT.value)
    ),
    db: Session = Depends(get_db),
) -> list[Tenant]:
    statement = select(Tenant).where(Tenant.id == identity.tenant_id).order_by(Tenant.created_at)
    return list(db.scalars(statement).all())


@router.post("", response_model=TenantResponse, status_code=status.HTTP_201_CREATED)
def create_tenant(
    payload: TenantCreate,
    identity: AuthenticatedIdentity = Depends(
        require_permission(
            PolicyAction.CREATE.value,
            PolicyResource.TENANT.value,
            resource_tenant_from_identity=False,
        )
    ),
    db: Session = Depends(get_db),
) -> Tenant:
    tenant = Tenant(name=payload.name, slug=payload.slug)
    db.add(tenant)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        logger.warning("Tenant creation rejected due to integrity constraint")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Tenant with this slug already exists",
        ) from None
    except Exception:
        db.rollback()
        logger.error("Unexpected error while creating tenant")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to create tenant",
        ) from None
    db.refresh(tenant)
    return tenant
