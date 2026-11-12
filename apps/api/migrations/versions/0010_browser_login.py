"""Restricted credentials for password-only browser authentication."""

from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        DO $$
        DECLARE name text;
        BEGIN
            FOREACH name IN ARRAY ARRAY['veriq_password_verifier', 'veriq_browser_issuer'] LOOP
                IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = name) THEN
                    EXECUTE format('CREATE ROLE %I NOLOGIN NOINHERIT', name);
                END IF;
                IF EXISTS (
                    SELECT FROM pg_roles WHERE rolname = name AND (
                        rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls
                        OR rolinherit OR oid IN (SELECT member FROM pg_auth_members)
                        OR oid IN (SELECT roleid FROM pg_auth_members)
                    )
                ) THEN RAISE EXCEPTION 'Unsafe browser auth role'; END IF;
            END LOOP;
        END;
        $$;
        GRANT USAGE ON SCHEMA public TO veriq_password_verifier, veriq_browser_issuer;
        GRANT SELECT (email_normalized, email_verified_at, password_hash)
            ON public.users TO veriq_session_store;

        CREATE FUNCTION public.veriq_password_candidate(p_email text)
        RETURNS TABLE (id uuid, credential_version bigint, password_hash text)
        LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
            SELECT u.id, u.credential_version, u.password_hash
            FROM public.users AS u
            WHERE u.email_normalized = p_email AND u.email_verified_at IS NOT NULL
                AND u.disabled_at IS NULL
        $$;

        CREATE FUNCTION public.veriq_password_confirm(
            p_id uuid, p_user uuid, p_version bigint, p_hash bytea, p_org uuid
        ) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
        BEGIN
            PERFORM pg_advisory_xact_lock(hashtextextended(p_user::text, 7007));
            IF NOT EXISTS (
                SELECT FROM public.users WHERE id = p_user AND email_verified_at IS NOT NULL
            ) THEN RETURN false; END IF;
            RETURN public.veriq_auth_confirm(p_id, p_user, p_version, p_hash, p_org, 0::smallint);
        END;
        $$;

        ALTER FUNCTION public.veriq_password_candidate(text) OWNER TO veriq_session_store;
        ALTER FUNCTION public.veriq_password_confirm(uuid, uuid, bigint, bytea, uuid)
            OWNER TO veriq_session_store;
        REVOKE ALL ON FUNCTION public.veriq_password_candidate(text) FROM PUBLIC;
        REVOKE ALL ON FUNCTION public.veriq_password_confirm(uuid, uuid, bigint, bytea, uuid)
            FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION public.veriq_password_candidate(text) TO veriq_password_verifier;
        GRANT EXECUTE ON FUNCTION public.veriq_password_confirm(uuid, uuid, bigint, bytea, uuid)
            TO veriq_password_verifier;
        GRANT EXECUTE ON FUNCTION public.veriq_auth_issue(uuid, bytea, uuid, bytea, interval[], uuid, uuid, uuid)
            TO veriq_browser_issuer;
    """)


def downgrade() -> None:
    op.execute("""
        REVOKE EXECUTE ON FUNCTION public.veriq_auth_issue(uuid, bytea, uuid, bytea, interval[], uuid, uuid, uuid)
            FROM veriq_browser_issuer;
        DROP FUNCTION public.veriq_password_confirm(uuid, uuid, bigint, bytea, uuid);
        DROP FUNCTION public.veriq_password_candidate(text);
        REVOKE SELECT (email_normalized, email_verified_at, password_hash)
            ON public.users FROM veriq_session_store;
        REVOKE USAGE ON SCHEMA public FROM veriq_password_verifier, veriq_browser_issuer;
    """)
