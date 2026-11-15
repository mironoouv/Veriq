"""Store non-overlapping student participation intervals by tenant and group."""

from alembic import op

revision = "0025"
down_revision = "0024"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE EXTENSION IF NOT EXISTS btree_gist WITH SCHEMA public;

        CREATE TABLE public.group_memberships (
            organization_id uuid NOT NULL,
            id uuid NOT NULL,
            group_id uuid NOT NULL,
            membership_id uuid NOT NULL,
            start_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            end_at timestamptz,
            PRIMARY KEY (organization_id, id),
            FOREIGN KEY (organization_id, group_id)
                REFERENCES public.study_groups (organization_id, id),
            FOREIGN KEY (organization_id, membership_id)
                REFERENCES public.organization_memberships (organization_id, id),
            CHECK (isfinite(start_at) AND
                (end_at IS NULL OR (isfinite(end_at) AND end_at > start_at))),
            CONSTRAINT group_memberships_no_overlap EXCLUDE USING gist (
                organization_id WITH =,
                group_id WITH =,
                membership_id WITH =,
                tstzrange(start_at, end_at, '[)') WITH &&
            )
        );
        CREATE INDEX ix_group_memberships_member
            ON public.group_memberships (organization_id, membership_id);
        ALTER TABLE public.group_memberships ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.group_memberships FORCE ROW LEVEL SECURITY;
        REVOKE ALL ON public.group_memberships FROM PUBLIC, veriq_api, veriq_worker;
    """)


def downgrade() -> None:
    raise RuntimeError("Downgrading 0025 would discard group membership history")
