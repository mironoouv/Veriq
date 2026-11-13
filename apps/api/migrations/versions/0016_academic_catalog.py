"""Organization catalog and restricted runtime policies."""

from alembic import op

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None

TABLES = ("courses", "study_groups")
GRANTS = (
    "academic.catalog.read",
    "academic.catalog.archive",
    "academic.catalog.manage",
)


def upgrade() -> None:
    op.execute("""
        CREATE FUNCTION public.veriq_catalog_permission(tenant uuid, permission text)
        RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $$
            SELECT tenant::text=current_setting('veriq.organization_id',true)
                AND public.veriq_active_membership(tenant,current_setting('veriq.user_id',true))
                AND EXISTS (
                    SELECT FROM public.organization_memberships m
                    JOIN public.membership_roles r ON r.organization_id=m.organization_id
                        AND r.membership_id=m.id AND r.grant_epoch=m.grant_epoch
                    JOIN public.organization_role_permissions p ON p.organization_id=r.organization_id
                        AND p.role_id=r.role_id
                    WHERE m.organization_id=tenant AND m.user_id::text=current_setting('veriq.user_id',true)
                        AND m.status='active' AND p.permission_code=permission
                )
        $$;
        REVOKE ALL ON FUNCTION public.veriq_catalog_permission(uuid,text) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION public.veriq_catalog_permission(uuid,text) TO veriq_api;
    """)
    for grant in GRANTS:
        op.execute(f"""
            INSERT INTO public.permissions(scope,code) VALUES ('organization','{grant}');
            INSERT INTO public.organization_role_permissions(organization_id,role_id,permission_code)
                SELECT organization_id,id,'{grant}' FROM public.organization_roles WHERE code='org_admin';
        """)
    for table in TABLES:
        op.execute(f"""
            CREATE TABLE public.{table} (
                organization_id uuid NOT NULL REFERENCES public.organizations(id),
                id uuid NOT NULL,
                title text NOT NULL CHECK (title=btrim(title) AND char_length(title) BETWEEN 1 AND 160),
                description text CHECK (char_length(description)<=2000),
                status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','archived')),
                version integer NOT NULL DEFAULT 1 CHECK (version>=1),
                created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
                updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
                create_digest bytea NOT NULL CHECK (octet_length(create_digest)=32),
                PRIMARY KEY(organization_id,id)
            );
            CREATE INDEX ix_{table}_catalog_list ON public.{table}(organization_id,status,title,id);
            ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY;
            ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY;
            CREATE POLICY catalog_read ON public.{table} FOR SELECT TO veriq_api USING (
                public.veriq_catalog_permission(organization_id,'academic.catalog.read')
                AND (status='active' OR public.veriq_catalog_permission(organization_id,'academic.catalog.archive'))
            );
            CREATE POLICY catalog_insert ON public.{table} FOR INSERT TO veriq_api WITH CHECK (
                status='active' AND public.veriq_catalog_permission(organization_id,'academic.catalog.manage')
            );
            CREATE POLICY catalog_update ON public.{table} FOR UPDATE TO veriq_api USING (
                status='active' AND public.veriq_catalog_permission(organization_id,'academic.catalog.manage')
            ) WITH CHECK (
                public.veriq_catalog_permission(organization_id,'academic.catalog.manage')
                AND (status='active' OR public.veriq_catalog_permission(organization_id,'academic.catalog.archive'))
            );
            GRANT SELECT, INSERT ON public.{table} TO veriq_api;
            GRANT UPDATE (title,description,status,version,updated_at) ON public.{table} TO veriq_api;
        """)
    op.execute("""
        CREATE TABLE public.academic_catalog_events (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id uuid NOT NULL,
            actor_id uuid NOT NULL,
            course_id uuid,
            group_id uuid,
            action text NOT NULL CHECK (action IN ('create','edit','archive')),
            request_id uuid NOT NULL,
            created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            CHECK (num_nonnulls(course_id,group_id)=1),
            FOREIGN KEY(organization_id,actor_id) REFERENCES public.organization_memberships(organization_id,user_id),
            FOREIGN KEY(organization_id,course_id) REFERENCES public.courses(organization_id,id),
            FOREIGN KEY(organization_id,group_id) REFERENCES public.study_groups(organization_id,id)
        );
        ALTER TABLE public.academic_catalog_events ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.academic_catalog_events FORCE ROW LEVEL SECURITY;
        CREATE POLICY catalog_event ON public.academic_catalog_events FOR INSERT TO veriq_api WITH CHECK (
            actor_id::text=current_setting('veriq.user_id',true)
            AND public.veriq_catalog_permission(organization_id,'academic.catalog.manage')
        );
        GRANT INSERT ON public.academic_catalog_events TO veriq_api;
    """)


def downgrade() -> None:
    op.execute("""
        LOCK TABLE public.academic_catalog_events, public.courses, public.study_groups IN ACCESS EXCLUSIVE MODE;
        DO $$ BEGIN
            IF EXISTS (SELECT FROM public.courses) OR EXISTS (SELECT FROM public.study_groups)
            THEN RAISE EXCEPTION 'Downgrade requires an empty catalog'; END IF;
        END $$;
        DROP TABLE public.academic_catalog_events, public.courses, public.study_groups;
        DROP FUNCTION public.veriq_catalog_permission(uuid,text);
        DELETE FROM public.organization_role_permissions WHERE permission_code LIKE 'academic.catalog.%';
        DELETE FROM public.permissions WHERE scope='organization' AND code LIKE 'academic.catalog.%';
    """)
