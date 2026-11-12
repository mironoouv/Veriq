"""Add organization memberships without modifying existing tables."""

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "organization_memberships",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(9), nullable=False, server_default="pending"),
        sa.Column("joined_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_memberships_organization",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name="fk_memberships_user", ondelete="RESTRICT"
        ),
        sa.UniqueConstraint(
            "organization_id", "user_id", name="uq_memberships_organization_user"
        ),
        sa.UniqueConstraint(
            "organization_id", "id", name="uq_memberships_organization_id"
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'active', 'suspended', 'revoked')",
            name="ck_memberships_status",
        ),
        sa.CheckConstraint("version > 0", name="ck_memberships_version"),
    )
    op.create_index("ix_memberships_user_id", "organization_memberships", ["user_id"])


def downgrade() -> None:
    op.drop_table("organization_memberships")
