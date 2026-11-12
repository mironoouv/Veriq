"""Bind membership grants to a revocation epoch."""

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "organization_memberships",
        sa.Column("grant_epoch", sa.BigInteger(), nullable=False, server_default="0"),
    )
    op.add_column(
        "membership_roles",
        sa.Column("grant_epoch", sa.BigInteger(), nullable=False, server_default="0"),
    )
    # Revision 0004 recorded no revocation history. Require explicit re-grants.
    op.execute("""
        UPDATE organization_memberships AS m SET grant_epoch = 1
        WHERE EXISTS (
            SELECT 1 FROM membership_roles AS r
            WHERE r.organization_id = m.organization_id AND r.membership_id = m.id
        )
    """)
    op.drop_constraint("membership_roles_pkey", "membership_roles", type_="primary")
    op.create_primary_key(
        "membership_roles_pkey",
        "membership_roles",
        ["organization_id", "membership_id", "grant_epoch", "role_id"],
    )
    op.execute("""
        CREATE FUNCTION public.veriq_membership_grant_epoch() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog AS $$
        BEGIN
            IF TG_OP = 'INSERT' THEN
                NEW.grant_epoch := 0;
            ELSE
                NEW.grant_epoch := OLD.grant_epoch;
                IF NEW.status = 'revoked' AND OLD.status <> 'revoked' THEN
                    NEW.grant_epoch := OLD.grant_epoch + 1;
                END IF;
            END IF;
            RETURN NEW;
        END;
        $$;

        CREATE TRIGGER membership_grant_epoch
        BEFORE INSERT OR UPDATE ON organization_memberships
        FOR EACH ROW EXECUTE FUNCTION public.veriq_membership_grant_epoch();

        CREATE OR REPLACE FUNCTION public.veriq_require_active_membership() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog AS $$
        BEGIN
            IF TG_OP = 'UPDATE' THEN
                RAISE EXCEPTION 'Role assignment history is immutable'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_membership_roles_immutable';
            END IF;
            SELECT grant_epoch INTO NEW.grant_epoch
            FROM public.organization_memberships
            WHERE organization_id = NEW.organization_id AND id = NEW.membership_id
              AND status = 'active'
            FOR SHARE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'Role assignment requires an active membership'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_membership_roles_active';
            END IF;
            RETURN NEW;
        END;
        $$;
    """)


def downgrade() -> None:
    # 0004 cannot represent history without risking reactivation. Keep it intact.
    op.execute("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM membership_roles) THEN
                RAISE EXCEPTION 'Downgrade to 0004 requires empty membership_roles';
            END IF;
        END;
        $$;

        DROP TRIGGER membership_grant_epoch ON organization_memberships;
        DROP FUNCTION public.veriq_membership_grant_epoch();

        CREATE OR REPLACE FUNCTION public.veriq_require_active_membership() RETURNS trigger
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
    op.drop_constraint("membership_roles_pkey", "membership_roles", type_="primary")
    op.create_primary_key(
        "membership_roles_pkey",
        "membership_roles",
        ["organization_id", "membership_id", "role_id"],
    )
    op.drop_column("membership_roles", "grant_epoch")
    op.drop_column("organization_memberships", "grant_epoch")
