from sqlalchemy import ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Identity(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "identities"
    __table_args__ = (
        UniqueConstraint("tenant_id", "email", name="uq_identities_tenant_email"),
        Index(
            "uq_identities_external_issuer_subject",
            "external_issuer",
            "external_subject",
            unique=True,
        ),
    )

    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    identity_type: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    role: Mapped[str] = mapped_column(
        String(30), nullable=False, default="viewer", server_default="viewer"
    )
    external_issuer: Mapped[str | None] = mapped_column(String(500), nullable=True)
    external_subject: Mapped[str | None] = mapped_column(String(255), nullable=True)

    tenant = relationship("Tenant", back_populates="identities")
    audit_events = relationship("AuditEvent", back_populates="actor_identity")
