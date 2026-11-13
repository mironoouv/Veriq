"""Stage a separate trust boundary for MFA factor disable."""

from alembic import op

revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None

LIMITS = "ARRAY[interval '30 min', interval '8 hours', interval '2 hours', interval '12 hours']"
SIGNATURES = (
    "veriq_trusted_mfa_attest(uuid,uuid,uuid,uuid,bytea,uuid)",
    "veriq_trusted_mfa_disable(uuid,uuid,uuid,uuid,bytea,uuid,uuid)",
)


def upgrade() -> None:
    op.execute(f"""
        DO $$ BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='veriq_mfa_trusted') THEN
                CREATE ROLE veriq_mfa_trusted NOLOGIN NOINHERIT NOSUPERUSER
                    NOCREATEROLE NOCREATEDB NOBYPASSRLS;
            END IF;
            IF EXISTS (
                SELECT FROM pg_roles r WHERE r.rolname='veriq_mfa_trusted'
                AND (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication
                     OR rolbypassrls OR rolinherit
                     OR EXISTS (SELECT FROM pg_auth_members WHERE roleid=r.oid OR member=r.oid))
            ) THEN RAISE EXCEPTION 'Unsafe trusted MFA role'; END IF;
        END $$;
        GRANT USAGE ON SCHEMA public TO veriq_mfa_trusted;
        CREATE TABLE public.mfa_operation_attestations (
            id uuid PRIMARY KEY,
            user_id uuid NOT NULL,
            factor_id uuid NOT NULL,
            session_id uuid NOT NULL,
            organization_id uuid,
            authority_revision bigint NOT NULL,
            credential_version bigint NOT NULL,
            purpose text NOT NULL CHECK (purpose='factor_disable'),
            expires_at timestamptz NOT NULL,
            consumed_at timestamptz
        );
        ALTER TABLE public.mfa_operation_attestations ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.mfa_operation_attestations FORCE ROW LEVEL SECURITY;
        CREATE POLICY mfa_attestation_store ON public.mfa_operation_attestations
            TO veriq_session_store USING (true) WITH CHECK (true);
        GRANT SELECT, INSERT, UPDATE (consumed_at)
            ON public.mfa_operation_attestations TO veriq_session_store;
        GRANT SELECT (id) ON public.mfa_factors TO veriq_session_store;

        CREATE FUNCTION public.veriq_trusted_mfa_attest(
            p_id uuid,p_user uuid,p_factor uuid,p_session uuid,p_digest bytea,p_org uuid
        ) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp AS $$
        BEGIN
            PERFORM pg_advisory_xact_lock_shared(670013::bigint);
            PERFORM pg_advisory_xact_lock(hashtextextended(p_user::text,7007));
            IF public.veriq_session_current(p_session,p_digest,p_user,p_org,{LIMITS}) IS NOT TRUE
               OR NOT public.veriq_mfa_can_disable(p_user,{LIMITS}) THEN RETURN false; END IF;
            INSERT INTO public.mfa_operation_attestations
            SELECT p_id,p_user,p_factor,p_session,p_org,a.revision,u.credential_version,
                   'factor_disable',clock_timestamp()+interval '30 seconds',NULL
            FROM public.mfa_recovery_authority a,public.users u,public.mfa_factors f
            WHERE a.id AND u.id=p_user AND f.user_id=p_user AND f.id=p_factor
              AND f.confirmed_at IS NOT NULL
            ON CONFLICT DO NOTHING;
            RETURN FOUND;
        END $$;

        CREATE FUNCTION public.veriq_trusted_mfa_disable(
            p_id uuid,p_user uuid,p_factor uuid,p_session uuid,p_digest bytea,
            p_request uuid,p_correlation uuid
        ) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp AS $$
        DECLARE proof public.mfa_operation_attestations%ROWTYPE;
        BEGIN
            PERFORM pg_advisory_xact_lock_shared(670013::bigint);
            PERFORM pg_advisory_xact_lock(hashtextextended(p_user::text,7007));
            SELECT a.* INTO proof FROM public.mfa_operation_attestations a
            JOIN public.users u ON u.id=a.user_id AND u.credential_version=a.credential_version
            JOIN public.mfa_recovery_authority r ON r.id AND r.revision=a.authority_revision
            WHERE a.id=p_id AND a.user_id=p_user AND a.factor_id=p_factor
              AND a.session_id=p_session AND a.purpose='factor_disable'
              AND a.consumed_at IS NULL AND a.expires_at>clock_timestamp()
            FOR UPDATE OF a;
            IF NOT FOUND OR public.veriq_session_current(
                p_session,p_digest,p_user,proof.organization_id,{LIMITS}
            ) IS NOT TRUE OR NOT public.veriq_mfa_can_disable(p_user,{LIMITS}) THEN RETURN false; END IF;
            DELETE FROM public.mfa_factors WHERE id=p_factor AND user_id=p_user;
            IF NOT FOUND THEN RETURN false; END IF;
            UPDATE public.mfa_operation_attestations SET consumed_at=clock_timestamp() WHERE id=p_id;
            PERFORM public.veriq_mfa_reset_sessions(p_user);
            IF NOT public.veriq_auth_append_event(
                p_request,p_request,p_correlation,'mfa_attempt','succeeded',p_user,p_user,false
            ) THEN RAISE EXCEPTION 'Conflicting MFA audit event'; END IF;
            RETURN true;
        END $$;
    """)
    for signature in SIGNATURES:
        op.execute(f"""
            ALTER FUNCTION public.{signature} OWNER TO veriq_session_store;
            REVOKE ALL ON FUNCTION public.{signature} FROM PUBLIC;
            GRANT EXECUTE ON FUNCTION public.{signature} TO veriq_mfa_trusted;
        """)


def downgrade() -> None:
    raise RuntimeError("Downgrading 0022 would discard MFA attestation history")
