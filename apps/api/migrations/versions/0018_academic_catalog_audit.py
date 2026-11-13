"""Require a verified session and atomic audit for catalog mutations."""

from alembic import op

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None

TABLES = ("courses", "study_groups")


def upgrade() -> None:
    op.execute("""
        DO $$ BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='veriq_catalog_auditor') THEN
                CREATE ROLE veriq_catalog_auditor NOLOGIN NOINHERIT NOSUPERUSER
                    NOCREATEDB NOCREATEROLE NOBYPASSRLS;
            END IF;
        END $$;
        GRANT USAGE ON SCHEMA public TO veriq_catalog_auditor;
        GRANT EXECUTE ON FUNCTION public.veriq_session_current(uuid,bytea,uuid,uuid,interval[])
            TO veriq_catalog_auditor;
        REVOKE INSERT ON public.academic_catalog_events FROM veriq_api;
        DROP POLICY catalog_event ON public.academic_catalog_events;
        CREATE POLICY catalog_event ON public.academic_catalog_events
            FOR INSERT TO veriq_catalog_auditor WITH CHECK (true);

        CREATE FUNCTION public.veriq_catalog_audit() RETURNS trigger
        LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
        DECLARE
            actor uuid := nullif(current_setting('veriq.user_id',true),'')::uuid;
            sid uuid := nullif(current_setting('veriq.catalog_session_id',true),'')::uuid;
            digest bytea := decode(nullif(current_setting('veriq.catalog_session_digest',true),''),'hex');
            request uuid := nullif(current_setting('veriq.catalog_request_id',true),'')::uuid;
            event_action text;
        BEGIN
            PERFORM pg_advisory_xact_lock_shared(670013::bigint);
            IF NOT coalesce(public.veriq_session_current(
                sid,digest,actor,NEW.organization_id,
                ARRAY[interval '30 minutes',interval '8 hours',interval '2 hours',interval '12 hours']
            ),false) THEN
                RAISE EXCEPTION 'Catalog mutation requires a current session' USING ERRCODE='42501';
            END IF;
            IF TG_OP='INSERT' THEN
                event_action := 'create';
            ELSIF OLD.status=NEW.status THEN
                event_action := 'edit';
            ELSIF NEW.status='archived' THEN
                event_action := 'archive';
            ELSE
                event_action := 'restore';
            END IF;
            INSERT INTO public.academic_catalog_events(
                organization_id,actor_id,course_id,group_id,action,request_id
            ) VALUES (
                NEW.organization_id,actor,
                CASE WHEN TG_TABLE_NAME='courses' THEN NEW.id END,
                CASE WHEN TG_TABLE_NAME='study_groups' THEN NEW.id END,
                event_action,coalesce(request,gen_random_uuid())
            );
            RETURN NULL;
        END $$;
        ALTER FUNCTION public.veriq_catalog_audit() OWNER TO veriq_catalog_auditor;
        REVOKE ALL ON FUNCTION public.veriq_catalog_audit() FROM PUBLIC;
        GRANT INSERT ON public.academic_catalog_events TO veriq_catalog_auditor;
    """)
    for table in TABLES:
        op.execute(f"""
            CREATE TRIGGER catalog_audit AFTER INSERT OR UPDATE ON public.{table}
                FOR EACH ROW EXECUTE FUNCTION public.veriq_catalog_audit();
        """)


def downgrade() -> None:
    raise RuntimeError("Downgrading 0018 would remove mandatory catalog auditing")
