"""Add identity roles and OIDC subject mapping.

Revision ID: 7f5a21c8b3d4
Revises: db938206a4eb
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "7f5a21c8b3d4"
down_revision: Union[str, Sequence[str], None] = "db938206a4eb"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "identities",
        sa.Column("role", sa.String(length=30), server_default="viewer", nullable=False),
    )
    op.add_column(
        "identities",
        sa.Column("external_issuer", sa.String(length=500), nullable=True),
    )
    op.add_column(
        "identities",
        sa.Column("external_subject", sa.String(length=255), nullable=True),
    )
    op.create_index(
        "uq_identities_external_issuer_subject",
        "identities",
        ["external_issuer", "external_subject"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("uq_identities_external_issuer_subject", table_name="identities")
    op.drop_column("identities", "external_subject")
    op.drop_column("identities", "external_issuer")
    op.drop_column("identities", "role")
