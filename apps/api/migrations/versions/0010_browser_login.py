"""Restricted credentials for password-only browser authentication."""

from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE public.auth_audit_events DROP CONSTRAINT ck_auth_event_type;
        ALTER TABLE public.auth_audit_events ADD CONSTRAINT ck_auth_event_type CHECK (
            event_type IN ('registration_attempt', 'login_attempt', 'mfa_attempt',
                'password_reset_attempt', 'mfa_recovery_attempt', 'session_issued',
                'session_revoked', 'sessions_revoked', 'password_verified',
                'login_mfa_required', 'session_rotated')
        );

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
        GRANT UPDATE (password_hash) ON public.users TO veriq_session_store;

        CREATE FUNCTION public.veriq_password_candidate(p_email text)
        RETURNS TABLE (id uuid, credential_version bigint, password_hash text)
        LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
            SELECT u.id, u.credential_version, u.password_hash
            FROM public.users AS u
            WHERE u.email_normalized = p_email AND u.email_verified_at IS NOT NULL
                AND u.disabled_at IS NULL
        $$;

        CREATE FUNCTION public.veriq_password_confirm(
            p_id uuid, p_user uuid, p_version bigint, p_hash bytea, p_org uuid,
            p_expected text, p_replacement text, p_request uuid, p_correlation uuid
        ) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
        BEGIN
            PERFORM pg_advisory_xact_lock(hashtextextended(p_user::text, 7007));
            PERFORM 1 FROM public.users
            WHERE id = p_user AND email_verified_at IS NOT NULL AND disabled_at IS NULL
                AND credential_version = p_version AND password_hash = p_expected
            FOR UPDATE;
            IF NOT FOUND THEN RETURN false; END IF;

            IF p_replacement IS NOT NULL THEN
                UPDATE public.users SET password_hash = p_replacement
                WHERE id = p_user AND credential_version = p_version AND password_hash = p_expected;
                IF NOT FOUND THEN RETURN false; END IF;
            END IF;
            IF NOT public.veriq_auth_confirm(p_id, p_user, p_version, p_hash, p_org, 0::smallint) THEN
                RAISE EXCEPTION 'Credential confirmation failed under account lock';
            END IF;
            IF NOT public.veriq_auth_append_event(
                p_request, p_request, p_correlation, 'password_verified', 'succeeded', p_user, p_user, false
            ) THEN RAISE EXCEPTION 'Conflicting auth event ID'; END IF;
            RETURN true;
        END;
        $$;

        CREATE FUNCTION public.veriq_browser_issue(
            p_id uuid, p_hash bytea, p_session uuid, p_session_hash bytea, p_limits interval[],
            p_event uuid, p_request uuid, p_correlation uuid
        ) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
        DECLARE account uuid; org uuid;
        BEGIN
            SELECT p.user_id INTO account FROM public.auth_credential_proofs AS p
            WHERE p.id = p_id AND p.proof_hash = p_hash;
            IF NOT FOUND THEN RETURN 'denied'; END IF;
            PERFORM pg_advisory_xact_lock(hashtextextended(account::text, 7007));

            SELECT p.organization_id INTO org
            FROM public.auth_credential_proofs AS p
            JOIN public.users AS u ON u.id = p.user_id
            WHERE p.id = p_id AND p.proof_hash = p_hash AND p.consumed_at IS NULL
                AND p.mfa_level = 0 AND p.expires_at > clock_timestamp()
                AND u.credential_version = p.credential_version AND u.disabled_at IS NULL
                AND u.email_verified_at IS NOT NULL;
            IF NOT FOUND THEN RETURN 'denied'; END IF;
            IF public.veriq_auth_issue(
                p_id, p_hash, p_session, p_session_hash, p_limits, p_event, p_request, p_correlation
            ) THEN RETURN 'issued'; END IF;

            IF NOT EXISTS (SELECT FROM public.veriq_session_limits(account, org, 0::smallint, p_limits))
                AND EXISTS (SELECT FROM public.veriq_session_limits(account, org, 1::smallint, p_limits))
            THEN
                UPDATE public.auth_credential_proofs SET consumed_at = clock_timestamp() WHERE id = p_id;
                IF NOT public.veriq_auth_append_event(
                    p_event, p_request, p_correlation, 'login_mfa_required', 'denied', account, account, false
                ) THEN RAISE EXCEPTION 'Conflicting auth event ID'; END IF;
                RETURN 'mfa_required';
            END IF;
            RETURN 'denied';
        END;
        $$;

        CREATE FUNCTION public.veriq_browser_rotate(
            p_id uuid, p_hash bytea, p_limits interval[], p_next_id uuid, p_next_hash bytea,
            p_target uuid, p_event uuid, p_request uuid, p_correlation uuid
        ) RETURNS TABLE (user_id uuid, organization_id uuid, mfa_level smallint)
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
        DECLARE identity record;
        BEGIN
            IF p_next_id IS NULL OR p_next_hash IS NULL THEN RETURN; END IF;
            SELECT * INTO identity FROM public.veriq_session_use(
                p_id, p_hash, p_limits, p_next_id, p_next_hash, p_target
            );
            IF NOT FOUND THEN RETURN; END IF;
            IF NOT public.veriq_auth_append_event(
                p_event, p_request, p_correlation, 'session_rotated', 'succeeded',
                identity.user_id, identity.user_id, false
            ) THEN RAISE EXCEPTION 'Conflicting auth event ID'; END IF;
            RETURN QUERY SELECT identity.user_id, identity.organization_id, identity.mfa_level;
        END;
        $$;
        ALTER FUNCTION public.veriq_password_candidate(text) OWNER TO veriq_session_store;
        ALTER FUNCTION public.veriq_password_confirm(uuid, uuid, bigint, bytea, uuid, text, text, uuid, uuid)
            OWNER TO veriq_session_store;
        REVOKE ALL ON FUNCTION public.veriq_password_candidate(text) FROM PUBLIC;
        REVOKE ALL ON FUNCTION public.veriq_password_confirm(uuid, uuid, bigint, bytea, uuid, text, text, uuid, uuid)
            FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION public.veriq_password_candidate(text) TO veriq_password_verifier;
        GRANT EXECUTE ON FUNCTION public.veriq_password_confirm(uuid, uuid, bigint, bytea, uuid, text, text, uuid, uuid)
            TO veriq_password_verifier;
        ALTER FUNCTION public.veriq_browser_issue(uuid, bytea, uuid, bytea, interval[], uuid, uuid, uuid)
            OWNER TO veriq_session_store;
        ALTER FUNCTION public.veriq_browser_rotate(uuid, bytea, interval[], uuid, bytea, uuid, uuid, uuid, uuid)
            OWNER TO veriq_session_store;
        REVOKE ALL ON FUNCTION public.veriq_browser_issue(uuid, bytea, uuid, bytea, interval[], uuid, uuid, uuid)
            FROM PUBLIC;
        REVOKE ALL ON FUNCTION public.veriq_browser_rotate(uuid, bytea, interval[], uuid, bytea, uuid, uuid, uuid, uuid)
            FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION public.veriq_browser_issue(uuid, bytea, uuid, bytea, interval[], uuid, uuid, uuid)
            TO veriq_browser_issuer;
        GRANT EXECUTE ON FUNCTION public.veriq_browser_rotate(uuid, bytea, interval[], uuid, bytea, uuid, uuid, uuid, uuid)
            TO veriq_api;
    """)


def downgrade() -> None:
    op.execute("""
        DROP FUNCTION public.veriq_browser_issue(uuid, bytea, uuid, bytea, interval[], uuid, uuid, uuid);
        DROP FUNCTION public.veriq_browser_rotate(uuid, bytea, interval[], uuid, bytea, uuid, uuid, uuid, uuid);
        REVOKE UPDATE (password_hash) ON public.users FROM veriq_session_store;
        ALTER TABLE public.auth_audit_events DROP CONSTRAINT ck_auth_event_type;
        ALTER TABLE public.auth_audit_events ADD CONSTRAINT ck_auth_event_type CHECK (
            event_type IN ('registration_attempt', 'login_attempt', 'mfa_attempt',
                'password_reset_attempt', 'mfa_recovery_attempt', 'session_issued',
                'session_revoked', 'sessions_revoked')
        );
        DROP FUNCTION public.veriq_password_confirm(uuid, uuid, bigint, bytea, uuid, text, text, uuid, uuid);
        DROP FUNCTION public.veriq_password_candidate(text);
        REVOKE SELECT (email_normalized, email_verified_at, password_hash)
            ON public.users FROM veriq_session_store;
        REVOKE USAGE ON SCHEMA public FROM veriq_password_verifier, veriq_browser_issuer;
    """)
