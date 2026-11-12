"""Register pending accounts and deliver email proofs through a restricted outbox."""

from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None

FUNCTIONS = {
    "veriq_signup_start(uuid, text, text, uuid, bytea, bytea)": "veriq_api",
    "veriq_signup_resend(text, uuid, bytea, bytea)": "veriq_api",
    "veriq_signup_verify(uuid, bytea, text, text)": "veriq_api",
    "veriq_signup_mail_next()": "veriq_worker",
    "veriq_signup_mail_finish(uuid, boolean)": "veriq_worker",
}


def upgrade() -> None:
    op.execute("""
        CREATE TABLE public.email_verification_proofs (
            user_id uuid PRIMARY KEY REFERENCES public.users(id) ON DELETE RESTRICT,
            id uuid NOT NULL UNIQUE,
            email_normalized text NOT NULL,
            purpose text NOT NULL CHECK (purpose = 'verify_email'),
            digest bytea NOT NULL CHECK (octet_length(digest) = 32),
            pending_since timestamptz NOT NULL,
            expires_at timestamptz NOT NULL,
            consumed_at timestamptz
        );
        CREATE TABLE public.email_verification_outbox (
            proof_id uuid PRIMARY KEY REFERENCES public.email_verification_proofs(id)
                ON DELETE CASCADE,
            envelope bytea NOT NULL CHECK (octet_length(envelope) BETWEEN 1 AND 4096),
            available_at timestamptz NOT NULL DEFAULT now()
        );
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'veriq_signup_store') THEN
                CREATE ROLE veriq_signup_store NOLOGIN NOINHERIT;
            END IF;
            IF EXISTS (
                SELECT FROM pg_roles WHERE rolname = 'veriq_signup_store' AND (
                    rolcanlogin OR rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication
                    OR rolbypassrls OR rolinherit
                    OR oid IN (SELECT member FROM pg_auth_members)
                    OR oid IN (SELECT roleid FROM pg_auth_members)
                )
            ) THEN RAISE EXCEPTION 'Unsafe signup role'; END IF;
        END;
        $$;
        GRANT USAGE ON SCHEMA public TO veriq_signup_store;
        GRANT SELECT (id, email_normalized, email_verified_at, disabled_at),
            INSERT (id, email_normalized, password_hash, disabled_at),
            UPDATE (password_hash, disabled_at, email_verified_at, updated_at)
            ON public.users TO veriq_signup_store;
        GRANT SELECT, INSERT, UPDATE, DELETE ON public.email_verification_proofs,
            public.email_verification_outbox TO veriq_signup_store;
    """)
    op.execute("""
        CREATE FUNCTION public.veriq_signup_start(
            p_user uuid, p_email text, p_password text, p_id uuid, p_digest bytea, p_envelope bytea
        ) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
        DECLARE tick timestamptz := clock_timestamp();
        BEGIN
            INSERT INTO public.users (id, email_normalized, password_hash, disabled_at)
            VALUES (p_user, p_email, p_password, tick)
            ON CONFLICT (email_normalized) DO NOTHING;
            IF FOUND THEN
                INSERT INTO public.email_verification_proofs
                    (user_id, id, email_normalized, purpose, digest, pending_since, expires_at)
                VALUES (p_user, p_id, p_email, 'verify_email', p_digest, tick, tick + interval '30 minutes');
                INSERT INTO public.email_verification_outbox (proof_id, envelope)
                VALUES (p_id, p_envelope);
            END IF;
        END;
        $$;

        CREATE FUNCTION public.veriq_signup_resend(
            p_email text, p_id uuid, p_digest bytea, p_envelope bytea
        ) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
        DECLARE account uuid; old_id uuid;
        BEGIN
            SELECT id INTO account FROM public.users
            WHERE email_normalized = p_email AND email_verified_at IS NULL FOR UPDATE;
            IF NOT FOUND THEN RETURN; END IF;
            SELECT p.id INTO old_id FROM public.email_verification_proofs AS p
            JOIN public.users AS u ON u.id = p.user_id AND u.disabled_at = p.pending_since
            WHERE p.user_id = account AND p.email_normalized = p_email AND p.consumed_at IS NULL;
            IF NOT FOUND THEN RETURN; END IF;
            DELETE FROM public.email_verification_outbox WHERE proof_id = old_id;
            UPDATE public.email_verification_proofs SET id = p_id, digest = p_digest,
                expires_at = clock_timestamp() + interval '30 minutes'
            WHERE user_id = account;
            INSERT INTO public.email_verification_outbox (proof_id, envelope)
            VALUES (p_id, p_envelope);
        END;
        $$;

        CREATE FUNCTION public.veriq_signup_verify(
            p_id uuid, p_digest bytea, p_email text, p_password text
        ) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
        DECLARE account uuid; tick timestamptz;
        BEGIN
            SELECT user_id INTO account FROM public.email_verification_proofs
            WHERE id = p_id AND digest = p_digest AND email_normalized = p_email;
            IF NOT FOUND THEN RETURN false; END IF;
            PERFORM 1 FROM public.users WHERE id = account AND email_normalized = p_email
                AND email_verified_at IS NULL FOR UPDATE;
            IF NOT FOUND THEN RETURN false; END IF;
            tick := clock_timestamp();
            UPDATE public.users AS u
            SET email_verified_at = tick, updated_at = tick, disabled_at = NULL, password_hash = p_password
            FROM public.email_verification_proofs AS p
            WHERE u.id = account AND p.user_id = account AND u.disabled_at = p.pending_since
                AND p.id = p_id AND p.digest = p_digest AND p.email_normalized = p_email
                AND p.purpose = 'verify_email' AND p.consumed_at IS NULL AND p.expires_at > tick;
            IF NOT FOUND THEN RETURN false; END IF;
            UPDATE public.email_verification_proofs SET consumed_at = tick WHERE user_id = account;
            DELETE FROM public.email_verification_outbox WHERE proof_id = p_id;
            RETURN true;
        END;
        $$;

        CREATE FUNCTION public.veriq_signup_mail_next()
        RETURNS TABLE (proof_id uuid, envelope bytea)
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
            SELECT m.proof_id, m.envelope FROM public.email_verification_outbox AS m
            JOIN public.email_verification_proofs AS p ON p.id = m.proof_id
            WHERE m.available_at <= clock_timestamp() AND p.expires_at > clock_timestamp()
            ORDER BY m.available_at, m.proof_id LIMIT 1 FOR UPDATE OF m SKIP LOCKED
        $$;

        CREATE FUNCTION public.veriq_signup_mail_finish(p_id uuid, p_delivered boolean)
        RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
        BEGIN
            IF p_delivered THEN
                DELETE FROM public.email_verification_outbox WHERE proof_id = p_id;
            ELSE
                UPDATE public.email_verification_outbox SET available_at = clock_timestamp() + interval '10 seconds'
                WHERE proof_id = p_id;
            END IF;
            DELETE FROM public.email_verification_outbox AS m WHERE m.proof_id IN (
                SELECT expired.proof_id FROM public.email_verification_outbox AS expired
                JOIN public.email_verification_proofs AS p ON p.id = expired.proof_id
                WHERE p.expires_at <= clock_timestamp()
                LIMIT 100 FOR UPDATE OF expired SKIP LOCKED
            );
        END;
        $$;
    """)
    for signature, caller in FUNCTIONS.items():
        op.execute(f"ALTER FUNCTION public.{signature} OWNER TO veriq_signup_store")
        op.execute(f"REVOKE ALL ON FUNCTION public.{signature} FROM PUBLIC")
        op.execute(f"GRANT EXECUTE ON FUNCTION public.{signature} TO {caller}")


def downgrade() -> None:
    op.execute("""
        LOCK TABLE public.email_verification_proofs IN ACCESS EXCLUSIVE MODE;
        DO $$
        BEGIN
            IF EXISTS (SELECT FROM public.email_verification_proofs) THEN
                RAISE EXCEPTION 'Downgrade would remove registration history';
            END IF;
        END;
        $$;
    """)
    for signature in reversed(FUNCTIONS):
        op.execute(f"DROP FUNCTION public.{signature}")
    op.execute("""
        DROP TABLE public.email_verification_outbox, public.email_verification_proofs;
        REVOKE SELECT (id, email_normalized, email_verified_at, disabled_at),
            INSERT (id, email_normalized, password_hash, disabled_at),
            UPDATE (password_hash, disabled_at, email_verified_at, updated_at)
            ON public.users FROM veriq_signup_store;
        REVOKE USAGE ON SCHEMA public FROM veriq_signup_store;
    """)
