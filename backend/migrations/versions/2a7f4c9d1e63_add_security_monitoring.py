"""Add event normalization fields and tenant-scoped alert management."""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "2a7f4c9d1e63"
down_revision: Union[str, Sequence[str], None] = "91d8a40e72bc"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "security_events",
        sa.Column("event_timestamp", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "security_events",
        sa.Column("origin", sa.String(length=20), nullable=True),
    )
    op.execute(
        sa.text(
            "UPDATE security_events "
            "SET event_timestamp = created_at, origin = 'manual'"
        )
    )
    with op.batch_alter_table("security_events") as batch_op:
        batch_op.alter_column(
            "event_timestamp",
            existing_type=sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        )
        batch_op.alter_column(
            "origin",
            existing_type=sa.String(length=20),
            nullable=False,
            server_default="manual",
        )
    op.create_index(
        "ix_security_events_event_timestamp",
        "security_events",
        ["event_timestamp"],
    )

    op.create_table(
        "alerts",
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("event_id", sa.String(length=36), nullable=False),
        sa.Column("rule_id", sa.String(length=100), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("description", sa.String(length=500), nullable=False),
        sa.Column(
            "status",
            sa.String(length=20),
            server_default="New",
            nullable=False,
        ),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'informational')",
            name="ck_alerts_severity",
        ),
        sa.CheckConstraint(
            "status IN ('New', 'Acknowledged', 'Resolved')",
            name="ck_alerts_status",
        ),
        sa.ForeignKeyConstraint(
            ["event_id"], ["security_events.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "event_id",
            "rule_id",
            name="uq_alerts_tenant_event_rule",
        ),
    )
    op.create_index("ix_alerts_tenant_status", "alerts", ["tenant_id", "status"])


def downgrade() -> None:
    op.drop_index("ix_alerts_tenant_status", table_name="alerts")
    op.drop_table("alerts")
    op.drop_index(
        "ix_security_events_event_timestamp",
        table_name="security_events",
    )
    with op.batch_alter_table("security_events") as batch_op:
        batch_op.drop_column("origin")
        batch_op.drop_column("event_timestamp")
