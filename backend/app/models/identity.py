from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Identity(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "identities"
    __table_args__ = (
        UniqueConstraint("tenant_id", "email", name="uq_identities_tenant_email"),
    )

    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    identity_type: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")

    tenant = relationship("Tenant", back_populates="identities")
    audit_events = relationship("AuditEvent", back_populates="actor_identity")
