from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, case, func, select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability
from app.security.authentication import AuthenticatedIdentity
from app.security.policy import PolicyAction, PolicyResource, require_permission
from app.schemas.vulnerability import (
    VulnerabilityCreate,
    VulnerabilityResponse,
    VulnerabilitySeverity,
    VulnerabilityStatus,
    VulnerabilitySummary,
    VulnerabilityUpdate,
)

router = APIRouter(prefix="/api/v1/vulnerabilities", tags=["Vulnerabilities"])


def _owned_asset_id(db: Session, asset_id: UUID, tenant_id: str) -> str:
    asset = db.scalar(
        select(Asset.id).where(
            Asset.id == str(asset_id),
            Asset.tenant_id == tenant_id,
        )
    )
    if asset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found",
        )
    return asset


def _get_tenant_vulnerability(
    db: Session,
    vulnerability_id: UUID,
    tenant_id: str,
) -> Vulnerability:
    vulnerability = db.scalar(
        select(Vulnerability).where(
            Vulnerability.id == str(vulnerability_id),
            Vulnerability.tenant_id == tenant_id,
        )
    )
    if vulnerability is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found",
        )
    return vulnerability


@router.get("", response_model=list[VulnerabilityResponse])
def list_vulnerabilities(
    severity: VulnerabilitySeverity | None = None,
    status_filter: VulnerabilityStatus | None = Query(default=None, alias="status"),
    asset_id: UUID | None = None,
    cve_id: str | None = None,
    identity: AuthenticatedIdentity = Depends(
        require_permission(
            PolicyAction.READ.value,
            PolicyResource.VULNERABILITY.value,
        )
    ),
    db: Session = Depends(get_db),
) -> list[Vulnerability]:
    statement = select(Vulnerability).where(
        Vulnerability.tenant_id == identity.tenant_id
    )
    if severity is not None:
        statement = statement.where(Vulnerability.severity == severity)
    if status_filter is not None:
        statement = statement.where(Vulnerability.status == status_filter)
    if asset_id is not None:
        statement = statement.where(Vulnerability.asset_id == str(asset_id))
    if cve_id is not None:
        statement = statement.where(Vulnerability.cve_id == cve_id)
    statement = statement.order_by(Vulnerability.first_detected_at.desc())
    return list(db.scalars(statement).all())


@router.post(
    "",
    response_model=VulnerabilityResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_vulnerability(
    payload: VulnerabilityCreate,
    identity: AuthenticatedIdentity = Depends(
        require_permission(
            PolicyAction.CREATE.value,
            PolicyResource.VULNERABILITY.value,
        )
    ),
    db: Session = Depends(get_db),
) -> Vulnerability:
    owned_asset_id = _owned_asset_id(db, payload.asset_id, identity.tenant_id)
    vulnerability = Vulnerability(
        tenant_id=identity.tenant_id,
        asset_id=owned_asset_id,
        title=payload.title,
        description=payload.description,
        cve_id=payload.cve_id,
        cvss_score=payload.cvss_score,
        severity=payload.severity,
        status=payload.status,
        detection_source=payload.detection_source,
        remediation_recommendation=payload.remediation_recommendation,
        remediation_due_date=payload.remediation_due_date,
    )
    db.add(vulnerability)
    db.commit()
    db.refresh(vulnerability)
    return vulnerability


@router.get("/summary", response_model=VulnerabilitySummary)
def vulnerability_summary(
    identity: AuthenticatedIdentity = Depends(
        require_permission(
            PolicyAction.READ.value,
            PolicyResource.VULNERABILITY.value,
        )
    ),
    db: Session = Depends(get_db),
) -> VulnerabilitySummary:
    today = datetime.now(timezone.utc).date()
    overdue_filter = and_(
        Vulnerability.remediation_due_date < today,
        Vulnerability.status.in_(("Open", "In Progress")),
    )
    statement = (
        select(
            func.count(Vulnerability.id),
            func.coalesce(
                func.sum(case((Vulnerability.severity == "Critical", 1), else_=0)),
                0,
            ),
            func.coalesce(
                func.sum(case((Vulnerability.severity == "High", 1), else_=0)),
                0,
            ),
            func.coalesce(
                func.sum(case((Vulnerability.severity == "Medium", 1), else_=0)),
                0,
            ),
            func.coalesce(
                func.sum(case((Vulnerability.severity == "Low", 1), else_=0)),
                0,
            ),
            func.coalesce(
                func.sum(case((Vulnerability.status == "Open", 1), else_=0)),
                0,
            ),
            func.coalesce(
                func.sum(case((Vulnerability.status == "Resolved", 1), else_=0)),
                0,
            ),
            func.coalesce(
                func.sum(case((overdue_filter, 1), else_=0)),
                0,
            ),
        ).where(Vulnerability.tenant_id == identity.tenant_id)
    )
    counts = db.execute(statement).one()
    return VulnerabilitySummary(
        total_vulnerabilities=counts[0],
        critical_findings=counts[1],
        high_findings=counts[2],
        medium_findings=counts[3],
        low_findings=counts[4],
        open_findings=counts[5],
        resolved_findings=counts[6],
        overdue_findings=counts[7],
    )


@router.get("/{vulnerability_id}", response_model=VulnerabilityResponse)
def get_vulnerability(
    vulnerability_id: UUID,
    identity: AuthenticatedIdentity = Depends(
        require_permission(
            PolicyAction.READ.value,
            PolicyResource.VULNERABILITY.value,
        )
    ),
    db: Session = Depends(get_db),
) -> Vulnerability:
    return _get_tenant_vulnerability(db, vulnerability_id, identity.tenant_id)


@router.patch(
    "/{vulnerability_id}",
    response_model=VulnerabilityResponse,
)
def update_vulnerability(
    vulnerability_id: UUID,
    payload: VulnerabilityUpdate,
    identity: AuthenticatedIdentity = Depends(
        require_permission(
            PolicyAction.UPDATE.value,
            PolicyResource.VULNERABILITY.value,
        )
    ),
    db: Session = Depends(get_db),
) -> Vulnerability:
    vulnerability = _get_tenant_vulnerability(
        db,
        vulnerability_id,
        identity.tenant_id,
    )
    updates = payload.model_dump(exclude_unset=True)
    if "asset_id" in updates:
        updates["asset_id"] = _owned_asset_id(
            db,
            updates["asset_id"],
            identity.tenant_id,
        )
    for field, value in updates.items():
        setattr(vulnerability, field, value)
    db.commit()
    db.refresh(vulnerability)
    return vulnerability
