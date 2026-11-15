"""Store explicit group-scoped Teacher assignments without runtime access."""

from alembic import op

revision = "0024"
down_revision = "0023"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE public.academic_group_teacher_assignments (
            organization_id uuid NOT NULL,
            id uuid NOT NULL,
            group_id uuid NOT NULL,
            membership_id uuid NOT NULL,
            grant_epoch bigint NOT NULL CHECK (grant_epoch >= 0),
            granted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            revoked_at timestamptz CHECK (revoked_at >= granted_at),
            PRIMARY KEY (organization_id, id),
            FOREIGN KEY (organization_id, group_id)
                REFERENCES public.study_groups (organization_id, id),
            FOREIGN KEY (organization_id, membership_id)
                REFERENCES public.organization_memberships (organization_id, id)
        );
        CREATE UNIQUE INDEX uq_group_teacher_assignment_open
            ON public.academic_group_teacher_assignments
               (organization_id, group_id, membership_id, grant_epoch)
            WHERE revoked_at IS NULL;
        CREATE INDEX ix_group_teacher_assignment_membership
            ON public.academic_group_teacher_assignments (organization_id, membership_id);
        ALTER TABLE public.academic_group_teacher_assignments ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.academic_group_teacher_assignments FORCE ROW LEVEL SECURITY;
        REVOKE ALL ON public.academic_group_teacher_assignments
            FROM PUBLIC, veriq_api, veriq_worker;
    """)


def downgrade() -> None:
    raise RuntimeError("Downgrading 0024 would discard Teacher assignment history")
