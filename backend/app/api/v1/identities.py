from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.identity import Identity
from app.schemas.identity import IdentityResponse

router = APIRouter(prefix="/api/v1/identities", tags=["Identities"])


@router.get("", response_model=list[IdentityResponse])
def list_identities(db: Session = Depends(get_db)) -> list[Identity]:
    return list(db.scalars(select(Identity).order_by(Identity.created_at)).all())
