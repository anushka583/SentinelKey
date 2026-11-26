from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.asset import Asset
from app.security.authentication import AuthenticatedIdentity
from app.security.policy import PolicyAction, PolicyResource, require_permission
from app.schemas.asset import AssetResponse

router = APIRouter(prefix="/api/v1/assets", tags=["Assets"])


@router.get("", response_model=list[AssetResponse])
def list_assets(
    identity: AuthenticatedIdentity = Depends(
        require_permission(PolicyAction.READ.value, PolicyResource.ASSET.value)
    ),
    db: Session = Depends(get_db),
) -> list[Asset]:
    statement = (
        select(Asset)
        .where(Asset.tenant_id == identity.tenant_id)
        .order_by(Asset.created_at)
    )
    return list(db.scalars(statement).all())
