"""Separate platform and organization roles and their grants."""

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "permissions",
        sa.Column("scope", sa.String(), primary_key=True),
        sa.Column("code", sa.String(), primary_key=True),
        sa.CheckConstraint(
            "scope IN ('platform', 'organization')", name="ck_permissions_scope"
        ),
        sa.CheckConstraint("length(trim(code)) > 0", name="ck_permissions_code"),
    )
    op.create_table(
        "platform_roles",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("code", sa.String(), nullable=False),
        sa.UniqueConstraint("code", name="uq_platform_roles_code"),
        sa.CheckConstraint("code = 'superadmin'", name="ck_platform_roles_code"),
    )
    op.create_table(
        "organization_roles",
        sa.Column("organization_id", sa.Uuid(), primary_key=True),
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("code", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="RESTRICT"
        ),
        sa.UniqueConstraint(
            "organization_id", "code", name="uq_organization_roles_code"
        ),
        sa.CheckConstraint(
            "code IN ('org_admin', 'teacher', 'proctor', 'student', 'technician')",
            name="ck_organization_roles_code",
        ),
    )
    op.create_table(
        "platform_role_assignments",
        sa.Column("user_id", sa.Uuid(), primary_key=True),
        sa.Column("role_id", sa.Uuid(), primary_key=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["role_id"], ["platform_roles.id"], ondelete="RESTRICT"
        ),
    )
    op.create_index(
        "ix_platform_assignments_role", "platform_role_assignments", ["role_id"]
    )
    op.create_table(
        "platform_role_permissions",
        sa.Column("role_id", sa.Uuid(), primary_key=True),
        sa.Column("permission_code", sa.String(), primary_key=True),
        sa.Column("scope", sa.String(), nullable=False, server_default="platform"),
        sa.CheckConstraint(
            "scope = 'platform'", name="ck_platform_role_permissions_scope"
        ),
        sa.ForeignKeyConstraint(
            ["role_id"], ["platform_roles.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["scope", "permission_code"],
            ["permissions.scope", "permissions.code"],
            name="fk_platform_role_permissions_permission",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_platform_role_permissions_permission",
        "platform_role_permissions",
        ["scope", "permission_code"],
    )
    op.create_table(
        "organization_role_permissions",
        sa.Column("organization_id", sa.Uuid(), primary_key=True),
        sa.Column("role_id", sa.Uuid(), primary_key=True),
        sa.Column("permission_code", sa.String(), primary_key=True),
        sa.Column("scope", sa.String(), nullable=False, server_default="organization"),
        sa.CheckConstraint(
            "scope = 'organization'", name="ck_organization_role_permissions_scope"
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "role_id"],
            ["organization_roles.organization_id", "organization_roles.id"],
            name="fk_organization_role_permissions_role",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["scope", "permission_code"],
            ["permissions.scope", "permissions.code"],
            name="fk_organization_role_permissions_permission",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_organization_role_permissions_permission",
        "organization_role_permissions",
        ["scope", "permission_code"],
    )
    op.create_table(
        "membership_roles",
        sa.Column("organization_id", sa.Uuid(), primary_key=True),
        sa.Column("membership_id", sa.Uuid(), primary_key=True),
        sa.Column("role_id", sa.Uuid(), primary_key=True),
        sa.ForeignKeyConstraint(
            ["organization_id", "membership_id"],
            ["organization_memberships.organization_id", "organization_memberships.id"],
            name="fk_membership_roles_membership",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "role_id"],
            ["organization_roles.organization_id", "organization_roles.id"],
            name="fk_membership_roles_role",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_membership_roles_role", "membership_roles", ["organization_id", "role_id"]
    )
    # Serialize assignment with changes to membership status without elevating privileges.
    op.execute("""
        CREATE FUNCTION veriq_require_active_membership() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog AS $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM public.organization_memberships
                WHERE organization_id = NEW.organization_id AND id = NEW.membership_id
                  AND status = 'active'
                FOR SHARE
            ) THEN
                RAISE EXCEPTION 'Role assignment requires an active membership'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_membership_roles_active';
            END IF;
            RETURN NEW;
        END;
        $$;
    """)
    op.execute("""
        CREATE TRIGGER membership_roles_require_active
        BEFORE INSERT OR UPDATE ON membership_roles
        FOR EACH ROW EXECUTE FUNCTION veriq_require_active_membership();
    """)


def downgrade() -> None:
    op.drop_table("membership_roles")
    op.execute("DROP FUNCTION veriq_require_active_membership()")
    op.drop_table("organization_role_permissions")
    op.drop_table("platform_role_permissions")
    op.drop_table("platform_role_assignments")
    op.drop_table("organization_roles")
    op.drop_table("platform_roles")
    op.drop_table("permissions")
