"""MFA factors, one-time challenges and scoped session assurance."""

from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE public.organization_mfa_policies (
            organization_id uuid PRIMARY KEY REFERENCES public.organizations(id),
            required boolean NOT NULL,
            revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0)
        );
        ALTER TABLE public.organization_mfa_policies ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.organization_mfa_policies FORCE ROW LEVEL SECURITY;
        CREATE POLICY mfa_policy_session_lookup ON public.organization_mfa_policies
            FOR SELECT TO veriq_session_store USING (true);
        CREATE TABLE public.mfa_factors (
            user_id uuid PRIMARY KEY REFERENCES public.users(id),
            id uuid NOT NULL UNIQUE,
            key_id text NOT NULL,
            ciphertext bytea NOT NULL,
            confirmed_at timestamptz,
            pending_until timestamptz NOT NULL,
            last_counter bigint NOT NULL DEFAULT -1
        );
        CREATE TABLE public.mfa_recovery_codes (
            factor_id uuid NOT NULL REFERENCES public.mfa_factors(id) ON DELETE CASCADE,
            salt bytea NOT NULL CHECK (octet_length(salt) = 16),
            digest bytea NOT NULL CHECK (octet_length(digest) = 32),
            used_at timestamptz,
            PRIMARY KEY (factor_id, digest)
        );
        CREATE TABLE public.mfa_challenges (
            id uuid PRIMARY KEY,
            digest bytea NOT NULL CHECK (octet_length(digest) = 32),
            user_id uuid NOT NULL REFERENCES public.users(id),
            factor_id uuid NOT NULL REFERENCES public.mfa_factors(id) ON DELETE CASCADE ON UPDATE CASCADE,
            organization_id uuid,
            credential_version bigint NOT NULL,
            purpose text NOT NULL CHECK (purpose IN ('login', 'enroll', 'sensitive', 'factor_disable')),
            session_id uuid REFERENCES public.auth_sessions(id) ON DELETE CASCADE,
            expires_at timestamptz NOT NULL,
            consumed_at timestamptz,
            CHECK ((purpose IN ('login', 'enroll')) = (session_id IS NULL))
        );
        CREATE INDEX ix_mfa_challenges_expires ON public.mfa_challenges(expires_at);
        CREATE TABLE public.mfa_session_assurance (
            session_id uuid PRIMARY KEY REFERENCES public.auth_sessions(id) ON DELETE CASCADE,
            purpose text NOT NULL CHECK (purpose IN ('sensitive', 'factor_disable')),
            verified_at timestamptz NOT NULL
        );

        DO $$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'veriq_mfa_verifier') THEN
                CREATE ROLE veriq_mfa_verifier NOLOGIN NOINHERIT;
            END IF;
            IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'veriq_mfa_verifier' AND
                (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls OR rolinherit
                 OR oid IN (SELECT member FROM pg_auth_members)
                 OR oid IN (SELECT roleid FROM pg_auth_members)))
            THEN RAISE EXCEPTION 'Unsafe MFA role'; END IF;
        END;
        $$;
        GRANT USAGE ON SCHEMA public TO veriq_mfa_verifier;
        GRANT SELECT, INSERT, UPDATE, DELETE ON public.mfa_factors, public.mfa_recovery_codes,
            public.mfa_challenges, public.mfa_session_assurance TO veriq_mfa_verifier;
        GRANT SELECT (user_id, confirmed_at, pending_until) ON public.mfa_factors TO veriq_session_store;
        GRANT SELECT ON public.organization_mfa_policies, public.mfa_session_assurance TO veriq_session_store;
        GRANT EXECUTE ON FUNCTION public.veriq_auth_append_event(uuid, uuid, uuid, text, text, uuid, uuid, boolean)
            TO veriq_mfa_verifier;
        GRANT EXECUTE ON FUNCTION public.veriq_auth_issue(uuid, bytea, uuid, bytea, interval[], uuid, uuid, uuid)
            TO veriq_mfa_verifier;
        GRANT EXECUTE ON FUNCTION public.veriq_session_use(uuid, bytea, interval[], uuid, bytea, uuid)
            TO veriq_mfa_verifier;
        ALTER FUNCTION public.veriq_session_limits(uuid, uuid, smallint, interval[])
            RENAME TO veriq_base_session_limits;

        CREATE FUNCTION public.veriq_session_limits(
            p_user uuid, p_org uuid, p_mfa smallint, p_limits interval[]
        ) RETURNS TABLE (epoch bigint, idle_limit interval, absolute_limit interval)
        LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
            SELECT base.epoch, base.idle_limit, base.absolute_limit
            FROM public.veriq_base_session_limits(p_user, p_org, p_mfa, p_limits) AS base
            WHERE p_mfa = 1 OR (
                NOT EXISTS (SELECT FROM public.organization_mfa_policies WHERE organization_id = p_org AND required)
                AND NOT EXISTS (SELECT FROM public.mfa_factors WHERE user_id = p_user AND confirmed_at IS NOT NULL)
            )
        $$;
        ALTER FUNCTION public.veriq_session_limits(uuid, uuid, smallint, interval[]) OWNER TO veriq_session_store;
        REVOKE ALL ON FUNCTION public.veriq_session_limits(uuid, uuid, smallint, interval[]) FROM PUBLIC;
    """)
    create_functions()


FUNCTIONS = {
    "veriq_mfa_primary(uuid, bytea, interval[])": "veriq_mfa_verifier",
    "veriq_mfa_account(uuid, bigint)": "veriq_mfa_verifier",
    "veriq_mfa_confirm(uuid, uuid, bigint, bytea, uuid)": "veriq_mfa_verifier",
    "veriq_mfa_can_disable(uuid, interval[])": "veriq_mfa_verifier",
    "veriq_mfa_reset_sessions(uuid)": "veriq_mfa_verifier",
    "veriq_mfa_fresh(uuid, bytea, interval[], text, interval)": "veriq_api, veriq_mfa_verifier",
}


def create_functions() -> None:
    op.execute("""
        CREATE FUNCTION public.veriq_mfa_primary(p_id uuid, p_digest bytea, p_limits interval[])
        RETURNS TABLE (user_id uuid, organization_id uuid, credential_version bigint)
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
        DECLARE account uuid; proof public.auth_credential_proofs%ROWTYPE;
        BEGIN
            SELECT p.user_id INTO account FROM public.auth_credential_proofs AS p
            WHERE p.id = p_id AND p.proof_hash = p_digest;
            IF NOT FOUND THEN RETURN; END IF;
            PERFORM pg_advisory_xact_lock(hashtextextended(account::text, 7007));
            SELECT p.* INTO proof FROM public.auth_credential_proofs AS p
            JOIN public.users AS u ON u.id = p.user_id
            WHERE p.id = p_id AND p.proof_hash = p_digest AND p.mfa_level = 0
                AND p.consumed_at IS NULL AND p.expires_at > clock_timestamp()
                AND p.credential_version = u.credential_version AND u.disabled_at IS NULL
                AND u.email_verified_at IS NOT NULL;
            IF NOT FOUND OR NOT EXISTS (
                SELECT FROM public.veriq_session_limits(account, proof.organization_id, 1::smallint, p_limits)
            ) THEN RETURN; END IF;
            IF NOT EXISTS (SELECT FROM public.mfa_factors AS f WHERE f.user_id = account
                          AND (f.confirmed_at IS NOT NULL OR f.pending_until > clock_timestamp()))
            THEN RETURN; END IF;
            UPDATE public.auth_credential_proofs SET consumed_at = clock_timestamp() WHERE id = p_id;
            RETURN QUERY SELECT proof.user_id, proof.organization_id, proof.credential_version;
        END;
        $$;

        CREATE FUNCTION public.veriq_mfa_account(p_user uuid, p_version bigint)
        RETURNS bigint LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
            SELECT u.credential_version FROM public.users AS u WHERE u.id = p_user
                AND u.disabled_at IS NULL AND u.email_verified_at IS NOT NULL
                AND (p_version IS NULL OR u.credential_version = p_version)
        $$;

        CREATE FUNCTION public.veriq_mfa_confirm(
            p_id uuid, p_user uuid, p_version bigint, p_digest bytea, p_org uuid
        ) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
        BEGIN
            PERFORM pg_advisory_xact_lock(hashtextextended(p_user::text, 7007));
            IF public.veriq_mfa_account(p_user, p_version) IS NULL OR NOT EXISTS (
                SELECT FROM public.mfa_factors WHERE user_id = p_user AND confirmed_at IS NOT NULL
            ) THEN RETURN false; END IF;
            RETURN public.veriq_auth_confirm(p_id, p_user, p_version, p_digest, p_org, 1::smallint);
        END;
        $$;

        CREATE FUNCTION public.veriq_mfa_can_disable(p_user uuid, p_limits interval[])
        RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
            SELECT EXISTS (SELECT FROM public.veriq_base_session_limits(p_user, NULL, 0::smallint, p_limits))
            AND NOT EXISTS (
                SELECT FROM public.organization_memberships AS m WHERE m.user_id = p_user
                    AND public.veriq_active_membership(m.organization_id, p_user::text)
                    AND (
                        NOT EXISTS (SELECT FROM public.veriq_base_session_limits(p_user, m.organization_id, 0::smallint, p_limits))
                        OR EXISTS (SELECT FROM public.organization_mfa_policies WHERE organization_id = m.organization_id AND required)
                    )
            )
        $$;

        CREATE FUNCTION public.veriq_mfa_reset_sessions(p_user uuid) RETURNS void
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
        BEGIN
            PERFORM pg_advisory_xact_lock(hashtextextended(p_user::text, 7007));
            UPDATE public.auth_sessions SET revoked_at = greatest(clock_timestamp(), last_seen_at),
                revoke_reason = 'account_logout' WHERE user_id = p_user AND revoked_at IS NULL;
            UPDATE public.users SET credential_version = credential_version + 1 WHERE id = p_user;
        END;
        $$;

        CREATE FUNCTION public.veriq_mfa_fresh(
            p_id uuid, p_digest bytea, p_limits interval[], p_purpose text, p_max_age interval
        ) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
            SELECT EXISTS (
                SELECT FROM public.auth_sessions AS s JOIN public.mfa_session_assurance AS a ON a.session_id = s.id
                WHERE s.id = p_id AND a.purpose = p_purpose AND s.mfa_level = 1
                    AND p_max_age > interval '0 seconds' AND p_max_age <= interval '5 minutes'
                    AND a.verified_at > statement_timestamp() - p_max_age
                    AND public.veriq_session_current(p_id, p_digest, s.user_id, s.organization_id, p_limits)
            )
        $$;
    """)
    for signature, caller in FUNCTIONS.items():
        op.execute(f"ALTER FUNCTION public.{signature} OWNER TO veriq_session_store")
        op.execute(f"REVOKE ALL ON FUNCTION public.{signature} FROM PUBLIC")
        op.execute(f"GRANT EXECUTE ON FUNCTION public.{signature} TO {caller}")


def downgrade() -> None:
    op.execute("""
        LOCK TABLE public.mfa_factors, public.organization_mfa_policies IN ACCESS EXCLUSIVE MODE;
        DO $$
        BEGIN
            IF EXISTS (SELECT FROM public.mfa_factors) OR
               EXISTS (SELECT FROM public.organization_mfa_policies)
            THEN RAISE EXCEPTION 'Downgrade requires empty MFA and policy tables'; END IF;
        END;
        $$;
    """)
    for signature in reversed(FUNCTIONS):
        op.execute(f"DROP FUNCTION public.{signature}")
    op.execute("""
        DROP FUNCTION public.veriq_session_limits(uuid, uuid, smallint, interval[]);
        ALTER FUNCTION public.veriq_base_session_limits(uuid, uuid, smallint, interval[])
            RENAME TO veriq_session_limits;
        REVOKE EXECUTE ON FUNCTION public.veriq_auth_append_event(uuid, uuid, uuid, text, text, uuid, uuid, boolean)
            FROM veriq_mfa_verifier;
        REVOKE EXECUTE ON FUNCTION public.veriq_auth_issue(uuid, bytea, uuid, bytea, interval[], uuid, uuid, uuid)
            FROM veriq_mfa_verifier;
        REVOKE EXECUTE ON FUNCTION public.veriq_session_use(uuid, bytea, interval[], uuid, bytea, uuid)
            FROM veriq_mfa_verifier;
        REVOKE USAGE ON SCHEMA public FROM veriq_mfa_verifier;
        DROP TABLE public.mfa_session_assurance, public.mfa_challenges, public.mfa_recovery_codes,
            public.mfa_factors, public.organization_mfa_policies;
    """)
