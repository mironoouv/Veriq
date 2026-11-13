"""Allow an authorized, audited return from the catalog archive."""

from alembic import op

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None

TABLES = ("courses", "study_groups")


def upgrade() -> None:
    op.execute("""
        ALTER TABLE public.academic_catalog_events
            DROP CONSTRAINT academic_catalog_events_action_check,
            ADD CHECK (action IN ('create','edit','archive','restore'));
        CREATE FUNCTION public.veriq_catalog_restore_guard() RETURNS trigger
        LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
        BEGIN
            IF OLD.status='archived' AND (
                NEW.status <> 'active' OR NEW.title IS DISTINCT FROM OLD.title
                OR NEW.description IS DISTINCT FROM OLD.description
                OR NEW.version <> OLD.version + 1
            ) THEN
                RAISE EXCEPTION 'Invalid archive transition' USING ERRCODE='42501';
            END IF;
            RETURN NEW;
        END $$;
        REVOKE ALL ON FUNCTION public.veriq_catalog_restore_guard() FROM PUBLIC;
    """)
    for table in TABLES:
        op.execute(f"""
            CREATE POLICY catalog_restore ON public.{table} FOR UPDATE TO veriq_api
            USING (
                status='archived'
                AND public.veriq_catalog_permission(organization_id,'academic.catalog.manage')
                AND public.veriq_catalog_permission(organization_id,'academic.catalog.archive')
            ) WITH CHECK (
                status='active'
                AND public.veriq_catalog_permission(organization_id,'academic.catalog.manage')
            );
            CREATE TRIGGER catalog_restore_guard BEFORE UPDATE ON public.{table}
                FOR EACH ROW EXECUTE FUNCTION public.veriq_catalog_restore_guard();
        """)


def downgrade() -> None:
    op.execute("""
        LOCK TABLE public.academic_catalog_events IN ACCESS EXCLUSIVE MODE;
        ALTER TABLE public.academic_catalog_events
            DROP CONSTRAINT academic_catalog_events_action_check,
            ADD CHECK (action IN ('create','edit','archive'));
    """)
    for table in TABLES:
        op.execute(f"""
            DROP TRIGGER catalog_restore_guard ON public.{table};
            DROP POLICY catalog_restore ON public.{table};
        """)
    op.execute("DROP FUNCTION public.veriq_catalog_restore_guard()")
