"""Expose session-bound factor lookup and atomic TOTP counter consumption."""

from alembic import op

revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None

FUNCTIONS = (
    "veriq_trusted_mfa_factor(uuid,uuid,uuid,bytea,uuid)",
    "veriq_trusted_mfa_totp(uuid,uuid,uuid,uuid,bytea,uuid,bigint,bytea)",
)


def upgrade() -> None:
    op.execute("""
        GRANT SELECT (key_id,ciphertext,last_counter), UPDATE (last_counter)
            ON public.mfa_factors TO veriq_session_store;
        CREATE FUNCTION public.veriq_trusted_mfa_factor(
            u uuid,f uuid,s uuid,d bytea,o uuid
        ) RETURNS TABLE(key_id text,ciphertext bytea,tick bigint)
        LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
            SELECT m.key_id,m.ciphertext,floor(extract(epoch FROM clock_timestamp()))::bigint
            FROM public.mfa_factors m
            WHERE m.user_id=u AND m.id=f AND m.confirmed_at IS NOT NULL
              AND public.veriq_session_current(s,d,u,o,
                  ARRAY[interval '30 min',interval '8 hours',interval '2 hours',interval '12 hours'])
        $$;
        CREATE FUNCTION public.veriq_trusted_mfa_totp(
            p uuid,u uuid,f uuid,s uuid,d bytea,o uuid,c bigint,encrypted bytea
        ) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp AS $$
        DECLARE current_counter bigint;
        BEGIN
            PERFORM pg_advisory_xact_lock_shared(670013::bigint);
            PERFORM pg_advisory_xact_lock(hashtextextended(u::text,7007));
            SELECT floor(extract(epoch FROM clock_timestamp())/30)::bigint INTO current_counter;
            IF c IS NULL OR c NOT BETWEEN current_counter-1 AND current_counter THEN RETURN false; END IF;
            UPDATE public.mfa_factors SET last_counter=c
            WHERE user_id=u AND id=f AND confirmed_at IS NOT NULL
              AND ciphertext=encrypted AND last_counter<c;
            IF NOT FOUND THEN RETURN false; END IF;
            IF public.veriq_trusted_mfa_attest(p,u,f,s,d,o) IS NOT TRUE THEN
                RAISE EXCEPTION 'MFA attestation denied' USING ERRCODE='42501';
            END IF;
            RETURN true;
        END $$;
    """)
    for signature in FUNCTIONS:
        op.execute(f"""
            ALTER FUNCTION public.{signature} OWNER TO veriq_session_store;
            REVOKE ALL ON FUNCTION public.{signature} FROM PUBLIC;
            GRANT EXECUTE ON FUNCTION public.{signature} TO veriq_mfa_trusted;
        """)


def downgrade() -> None:
    for signature in FUNCTIONS:
        op.execute(f"DROP FUNCTION public.{signature}")
    op.execute("""
        REVOKE SELECT (key_id,ciphertext,last_counter), UPDATE (last_counter)
        ON public.mfa_factors FROM veriq_session_store
    """)
