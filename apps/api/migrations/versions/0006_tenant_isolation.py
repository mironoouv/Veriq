"""Install limited runtime roles and fail-closed tenant policies."""

from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None

TENANT_TABLES = {
    "organizations": "id",
    "organization_memberships": "organization_id",
    "organization_roles": "organization_id",
    "organization_role_permissions": "organization_id",
    "membership_roles": "organization_id",
}


def upgrade() -> None:
    op.execute("""
        DO $$
        DECLARE name text;
        BEGIN
            FOREACH name IN ARRAY ARRAY['veriq_api', 'veriq_worker', 'veriq_identity_lookup'] LOOP
                IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = name) THEN
                    EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEROLE
                                    NOCREATEDB NOINHERIT NOREPLICATION NOBYPASSRLS', name);
                END IF;
                IF EXISTS (
                    SELECT FROM pg_catalog.pg_roles
                    WHERE rolname = name AND (
                        rolsuper OR rolcreaterole OR rolcreatedb OR rolinherit OR
                        rolreplication OR rolbypassrls OR
                        (name = 'veriq_identity_lookup' AND rolcanlogin) OR
                        oid IN (SELECT member FROM pg_catalog.pg_auth_members)
                    )
                ) THEN
                    RAISE EXCEPTION 'Unsafe existing runtime role: %', name;
                END IF;
            END LOOP;
        END;
        $$;

        GRANT USAGE ON SCHEMA public TO veriq_api, veriq_worker, veriq_identity_lookup;
        GRANT SELECT, INSERT, UPDATE ON public.background_jobs TO veriq_worker;
        GRANT SELECT (id, disabled_at) ON public.users TO veriq_identity_lookup;
        GRANT SELECT (id, status) ON public.organizations TO veriq_identity_lookup;
        GRANT SELECT (organization_id, user_id, status)
            ON public.organization_memberships TO veriq_identity_lookup;

        CREATE POLICY identity_lookup ON public.organizations
            FOR SELECT TO veriq_identity_lookup USING (true);
        CREATE POLICY identity_lookup ON public.organization_memberships
            FOR SELECT TO veriq_identity_lookup USING (true);

        CREATE FUNCTION public.veriq_active_membership(tenant uuid, subject text) RETURNS boolean
        LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
            SELECT EXISTS (
                SELECT 1 FROM public.organization_memberships AS membership
                JOIN public.organizations AS org ON org.id = membership.organization_id
                JOIN public.users AS account ON account.id = membership.user_id
                WHERE membership.organization_id = tenant
                  AND membership.user_id = CASE WHEN pg_input_is_valid(subject, 'uuid')
                                               THEN subject::uuid END
                  AND membership.status = 'active'
                  AND org.status = 'active'
                  AND account.disabled_at IS NULL
            );
        $$;
        ALTER FUNCTION public.veriq_active_membership(uuid, text) OWNER TO veriq_identity_lookup;
        REVOKE ALL ON FUNCTION public.veriq_active_membership(uuid, text) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION public.veriq_active_membership(uuid, text) TO veriq_api;
    """)

    for table, tenant_column in TENANT_TABLES.items():
        predicate = f"""
            {tenant_column}::text = current_setting('veriq.organization_id', true)
            AND public.veriq_active_membership(
                {tenant_column}, current_setting('veriq.user_id', true)
            )
        """
        op.execute(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY")
        op.execute(f"""
            CREATE POLICY tenant_scope ON public.{table} TO veriq_api
            USING ({predicate}) WITH CHECK ({predicate})
        """)
        op.execute(f"GRANT SELECT ON public.{table} TO veriq_api")


def downgrade() -> None:
    for table in TENANT_TABLES:
        op.execute(f"REVOKE SELECT ON public.{table} FROM veriq_api")
        op.execute(f"DROP POLICY tenant_scope ON public.{table}")
        op.execute(f"ALTER TABLE public.{table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE public.{table} DISABLE ROW LEVEL SECURITY")
    op.execute("""
        DROP FUNCTION public.veriq_active_membership(uuid, text);
        DROP POLICY identity_lookup ON public.organizations;
        DROP POLICY identity_lookup ON public.organization_memberships;
        REVOKE SELECT (organization_id, user_id, status)
            ON public.organization_memberships FROM veriq_identity_lookup;
        REVOKE SELECT (id, status) ON public.organizations FROM veriq_identity_lookup;
        REVOKE SELECT (id, disabled_at) ON public.users FROM veriq_identity_lookup;
        REVOKE SELECT, INSERT, UPDATE ON public.background_jobs FROM veriq_worker;
        REVOKE USAGE ON SCHEMA public FROM veriq_api, veriq_worker, veriq_identity_lookup;
    """)
