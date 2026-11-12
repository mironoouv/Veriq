"""Password replacement under the session issuance lock and shared encrypted mail."""

from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None

FUNCTIONS = {
    "veriq_password_notice_claim(uuid)": "veriq_worker",
    "veriq_password_session_candidate(uuid, bytea, interval[])": "veriq_password_verifier",
    "veriq_password_change(uuid, bytea, interval[], bigint, text, text, uuid, uuid)": "veriq_password_verifier",
    "veriq_password_reset_start(text, uuid, bytea, bytea)": "veriq_api",
    "veriq_password_reset_finish(uuid, bytea, text, text, uuid, uuid)": "veriq_api",
}


def upgrade() -> None:
    op.execute("""
        ALTER TABLE public.mfa_challenges DROP CONSTRAINT mfa_challenges_purpose_check;
        ALTER TABLE public.mfa_challenges ADD CONSTRAINT mfa_challenges_purpose_check
            CHECK (purpose IN ('login', 'enroll', 'sensitive', 'factor_disable', 'password_change'));
        ALTER TABLE public.mfa_session_assurance DROP CONSTRAINT mfa_session_assurance_purpose_check;
        ALTER TABLE public.mfa_session_assurance ADD CONSTRAINT mfa_session_assurance_purpose_check
            CHECK (purpose IN ('sensitive', 'factor_disable', 'password_change'));

        CREATE TABLE public.password_reset_proofs (
            user_id uuid PRIMARY KEY REFERENCES public.users(id) ON DELETE RESTRICT,
            id uuid NOT NULL UNIQUE,
            email_normalized text NOT NULL,
            credential_version bigint NOT NULL,
            purpose text NOT NULL DEFAULT 'password_reset' CHECK (purpose = 'password_reset'),
            digest bytea NOT NULL CHECK (octet_length(digest) = 32),
            expires_at timestamptz NOT NULL,
            consumed_at timestamptz
        );
        ALTER TABLE public.email_verification_outbox
            DROP CONSTRAINT email_verification_outbox_proof_id_fkey;
        ALTER TABLE public.email_verification_outbox
            ADD COLUMN reset_id uuid REFERENCES public.password_reset_proofs(id) ON DELETE CASCADE,
            ADD COLUMN verification_id uuid GENERATED ALWAYS AS
                (CASE WHEN reset_id IS NULL THEN proof_id END) STORED,
            ADD FOREIGN KEY (verification_id) REFERENCES public.email_verification_proofs(id) ON DELETE CASCADE,
            ADD CONSTRAINT ck_mail_reset_id CHECK (reset_id IS NULL OR reset_id = proof_id);

        GRANT SELECT, INSERT, UPDATE ON public.password_reset_proofs TO veriq_session_store;
        GRANT SELECT (id, expires_at) ON public.password_reset_proofs TO veriq_signup_store;
        GRANT SELECT (proof_id), INSERT (proof_id, reset_id, envelope), DELETE
            ON public.email_verification_outbox TO veriq_session_store;

        GRANT SELECT ON public.notification_outbox TO veriq_session_store;
        GRANT UPDATE (claim_id, lease_until, attempts) ON public.notification_outbox TO veriq_session_store;
        GRANT SELECT (id, target_id, event_type, created_at) ON public.auth_audit_events TO veriq_session_store;

        ALTER TABLE public.auth_audit_events DROP CONSTRAINT ck_auth_event_notify;
        ALTER TABLE public.auth_audit_events ADD CONSTRAINT ck_auth_event_notify CHECK (
            NOT notify OR (target_id IS NOT NULL AND result = 'succeeded'
                AND event_type IN ('sessions_revoked', 'password_changed', 'password_reset'))
        );
        ALTER TABLE public.auth_audit_events DROP CONSTRAINT ck_auth_event_type;
        ALTER TABLE public.auth_audit_events ADD CONSTRAINT ck_auth_event_type CHECK (
            event_type IN ('registration_attempt', 'login_attempt', 'mfa_attempt',
                'password_reset_attempt', 'mfa_recovery_attempt', 'session_issued',
                'session_revoked', 'sessions_revoked', 'password_verified',
                'login_mfa_required', 'session_rotated', 'password_changed', 'password_reset')
        );
    """)
    configure_mail(True)
    create_functions()


def configure_mail(reset: bool) -> None:
    reset_join = (
        "LEFT JOIN public.password_reset_proofs AS r ON r.id = m.reset_id"
        if reset
        else ""
    )
    join_type = "LEFT JOIN" if reset else "JOIN"
    verification_column = "verification_id" if reset else "proof_id"
    expires = "coalesce(p.expires_at, r.expires_at)" if reset else "p.expires_at"
    op.execute(f"""
        CREATE OR REPLACE FUNCTION public.veriq_signup_mail_next()
        RETURNS TABLE (proof_id uuid, envelope bytea)
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
            SELECT m.proof_id, m.envelope FROM public.email_verification_outbox AS m
            {join_type} public.email_verification_proofs AS p ON p.id = m.{verification_column}
            {reset_join}
            WHERE m.available_at <= clock_timestamp() AND {expires} > clock_timestamp()
            ORDER BY m.available_at, m.proof_id LIMIT 1 FOR UPDATE OF m SKIP LOCKED
        $$;

        CREATE OR REPLACE FUNCTION public.veriq_signup_mail_finish(p_id uuid, p_delivered boolean)
        RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
        BEGIN
            IF p_delivered THEN
                DELETE FROM public.email_verification_outbox WHERE proof_id = p_id;
            ELSE
                UPDATE public.email_verification_outbox SET available_at = clock_timestamp() + interval '10 seconds'
                WHERE proof_id = p_id;
            END IF;
            DELETE FROM public.email_verification_outbox AS expired WHERE expired.proof_id IN (
                SELECT m.proof_id FROM public.email_verification_outbox AS m
                {join_type} public.email_verification_proofs AS p ON p.id = m.{verification_column}
                {reset_join}
                WHERE {expires} <= clock_timestamp()
                LIMIT 100 FOR UPDATE OF m SKIP LOCKED
            );
        END;
        $$;
    """)


def create_functions() -> None:
    op.execute("""
        CREATE FUNCTION public.veriq_password_notice_claim(p_claim uuid)
        RETURNS TABLE (event_id uuid, email text, event_type text)
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
            WITH candidate AS (
                SELECT n.event_id, u.email_normalized, e.event_type
                FROM public.notification_outbox AS n
                JOIN public.auth_audit_events AS e ON e.id=n.event_id
                JOIN public.users AS u ON u.id=e.target_id
                WHERE p_claim IS NOT NULL AND n.delivered_at IS NULL
                    AND (n.lease_until IS NULL OR n.lease_until <= clock_timestamp())
                    AND e.event_type IN ('password_changed', 'password_reset')
                    AND u.email_verified_at IS NOT NULL
                ORDER BY e.created_at,n.event_id LIMIT 1 FOR UPDATE OF n SKIP LOCKED
            )
            UPDATE public.notification_outbox AS n SET claim_id=p_claim,
                lease_until=clock_timestamp()+interval '30 seconds', attempts=n.attempts+1
            FROM candidate AS c WHERE n.event_id=c.event_id
            RETURNING n.event_id,c.email_normalized::text,c.event_type::text
        $$;
        CREATE FUNCTION public.veriq_password_session_candidate(
            p_id uuid, p_digest bytea, p_limits interval[]
        ) RETURNS TABLE (user_id uuid, credential_version bigint, password_hash text)
        LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
            SELECT u.id, u.credential_version, u.password_hash FROM public.auth_sessions AS s
            JOIN public.users AS u ON u.id = s.user_id
            WHERE s.id = p_id AND u.email_verified_at IS NOT NULL
                AND public.veriq_session_current(p_id, p_digest, s.user_id, s.organization_id, p_limits)
        $$;

        CREATE FUNCTION public.veriq_password_apply(
            p_user uuid, p_new text, p_type text, p_request uuid, p_correlation uuid
        ) RETURNS void LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
        BEGIN
            UPDATE public.users SET password_hash=p_new, updated_at=clock_timestamp() WHERE id=p_user;
            PERFORM public.veriq_mfa_reset_sessions(p_user);
            DELETE FROM public.email_verification_outbox WHERE proof_id IN (
                SELECT id FROM public.password_reset_proofs WHERE user_id=p_user
            );
            UPDATE public.password_reset_proofs SET consumed_at=clock_timestamp()
            WHERE user_id=p_user AND consumed_at IS NULL;
            IF NOT public.veriq_auth_append_event(
                p_request, p_request, p_correlation, p_type, 'succeeded', p_user, p_user, true
            ) THEN RAISE EXCEPTION 'Conflicting auth event ID'; END IF;
        END;
        $$;
        ALTER FUNCTION public.veriq_password_apply(uuid, text, text, uuid, uuid) OWNER TO veriq_session_store;
        REVOKE ALL ON FUNCTION public.veriq_password_apply(uuid, text, text, uuid, uuid) FROM PUBLIC;

        CREATE FUNCTION public.veriq_password_change(
            p_id uuid, p_digest bytea, p_limits interval[], p_version bigint,
            p_expected text, p_new text, p_request uuid, p_correlation uuid
        ) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
        DECLARE account uuid; org uuid;
        BEGIN
            SELECT user_id, organization_id INTO account, org FROM public.auth_sessions
            WHERE id=p_id AND token_hash=p_digest;
            IF NOT FOUND THEN RETURN false; END IF;
            PERFORM pg_advisory_xact_lock(hashtextextended(account::text,7007));
            PERFORM 1 FROM public.users WHERE id=account AND credential_version=p_version
                AND password_hash=p_expected AND email_verified_at IS NOT NULL AND disabled_at IS NULL
            FOR UPDATE;
            IF NOT FOUND OR p_new = p_expected OR NOT public.veriq_session_current(
                p_id,p_digest,account,org,p_limits
            ) THEN RETURN false; END IF;
            IF NOT EXISTS (SELECT FROM public.veriq_session_limits(account,org,0::smallint,p_limits))
                AND NOT public.veriq_mfa_fresh(p_id,p_digest,p_limits,'password_change',interval '5 minutes')
            THEN RETURN false; END IF;
            PERFORM public.veriq_password_apply(account,p_new,'password_changed',p_request,p_correlation);
            RETURN true;
        END;
        $$;

        CREATE FUNCTION public.veriq_password_reset_start(
            p_email text,p_id uuid,p_digest bytea,p_envelope bytea
        ) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
        DECLARE account uuid; version bigint; previous uuid;
        BEGIN
            SELECT id INTO account FROM public.users WHERE email_normalized=p_email
                AND email_verified_at IS NOT NULL AND disabled_at IS NULL;
            IF NOT FOUND THEN RETURN; END IF;
            PERFORM pg_advisory_xact_lock(hashtextextended(account::text,7007));
            SELECT credential_version INTO version FROM public.users WHERE id=account
                AND email_normalized=p_email AND email_verified_at IS NOT NULL AND disabled_at IS NULL;
            IF NOT FOUND THEN RETURN; END IF;
            IF EXISTS (SELECT FROM public.password_reset_proofs WHERE user_id=account
                AND credential_version=version AND email_normalized=p_email AND consumed_at IS NULL
                AND expires_at > clock_timestamp()) THEN RETURN; END IF;
            SELECT id INTO previous FROM public.password_reset_proofs WHERE user_id=account;
            DELETE FROM public.email_verification_outbox WHERE proof_id=previous;
            INSERT INTO public.password_reset_proofs (user_id,id,email_normalized,credential_version,digest,expires_at)
            VALUES (account,p_id,p_email,version,p_digest,clock_timestamp()+interval '30 minutes')
            ON CONFLICT (user_id) DO UPDATE SET id=excluded.id,email_normalized=excluded.email_normalized,
                credential_version=excluded.credential_version,digest=excluded.digest,
                expires_at=excluded.expires_at,consumed_at=NULL;
            INSERT INTO public.email_verification_outbox (proof_id,reset_id,envelope)
            VALUES (p_id,p_id,p_envelope);
        END;
        $$;

        CREATE FUNCTION public.veriq_password_reset_finish(
            p_id uuid,p_digest bytea,p_email text,p_new text,p_request uuid,p_correlation uuid
        ) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
        DECLARE account uuid;
        BEGIN
            SELECT user_id INTO account FROM public.password_reset_proofs
            WHERE id=p_id AND digest=p_digest AND email_normalized=p_email;
            IF NOT FOUND THEN RETURN false; END IF;
            PERFORM pg_advisory_xact_lock(hashtextextended(account::text,7007));
            PERFORM 1 FROM public.users AS u JOIN public.password_reset_proofs AS p ON p.user_id=u.id
            WHERE u.id=account AND u.email_normalized=p_email AND u.email_verified_at IS NOT NULL
                AND u.disabled_at IS NULL AND p.id=p_id AND p.digest=p_digest
                AND p.email_normalized=p_email AND p.purpose='password_reset'
                AND u.credential_version=p.credential_version AND p.consumed_at IS NULL
                AND p.expires_at > clock_timestamp() FOR UPDATE OF u;
            IF NOT FOUND THEN RETURN false; END IF;
            PERFORM public.veriq_password_apply(account,p_new,'password_reset',p_request,p_correlation);
            RETURN true;
        END;
        $$;

        GRANT UPDATE (updated_at) ON public.users TO veriq_session_store;
    """)
    for signature, caller in FUNCTIONS.items():
        op.execute(f"ALTER FUNCTION public.{signature} OWNER TO veriq_session_store")
        op.execute(f"REVOKE ALL ON FUNCTION public.{signature} FROM PUBLIC")
        op.execute(f"GRANT EXECUTE ON FUNCTION public.{signature} TO {caller}")


def downgrade() -> None:
    op.execute("""
        LOCK TABLE public.password_reset_proofs, public.auth_audit_events,
            public.mfa_challenges, public.mfa_session_assurance IN ACCESS EXCLUSIVE MODE;
        DO $$
        BEGIN
            IF EXISTS (SELECT FROM public.password_reset_proofs) OR EXISTS (
                SELECT FROM public.auth_audit_events WHERE event_type IN ('password_changed','password_reset')
            ) OR EXISTS (SELECT FROM public.mfa_challenges WHERE purpose='password_change')
              OR EXISTS (SELECT FROM public.mfa_session_assurance WHERE purpose='password_change')
            THEN RAISE EXCEPTION 'Downgrade requires empty password recovery history'; END IF;
        END;
        $$;
    """)
    for signature in reversed(FUNCTIONS):
        op.execute(f"DROP FUNCTION public.{signature}")
    op.execute(
        "DROP FUNCTION public.veriq_password_apply(uuid, text, text, uuid, uuid)"
    )
    configure_mail(False)
    op.execute("""
        REVOKE UPDATE (updated_at) ON public.users FROM veriq_session_store;
        REVOKE SELECT, UPDATE (claim_id, lease_until, attempts) ON public.notification_outbox
            FROM veriq_session_store;
        REVOKE SELECT (id, target_id, event_type, created_at) ON public.auth_audit_events
            FROM veriq_session_store;
        ALTER TABLE public.auth_audit_events DROP CONSTRAINT ck_auth_event_notify;
        ALTER TABLE public.auth_audit_events ADD CONSTRAINT ck_auth_event_notify CHECK (
            NOT notify OR (target_id IS NOT NULL AND result = 'succeeded' AND event_type = 'sessions_revoked')
        );
        REVOKE SELECT (proof_id), INSERT (proof_id, reset_id, envelope), DELETE
            ON public.email_verification_outbox FROM veriq_session_store;
        ALTER TABLE public.email_verification_outbox DROP CONSTRAINT ck_mail_reset_id,
            DROP COLUMN verification_id, DROP COLUMN reset_id;
        ALTER TABLE public.email_verification_outbox ADD CONSTRAINT email_verification_outbox_proof_id_fkey
            FOREIGN KEY (proof_id) REFERENCES public.email_verification_proofs(id) ON DELETE CASCADE;
        DROP TABLE public.password_reset_proofs;
        ALTER TABLE public.mfa_challenges DROP CONSTRAINT mfa_challenges_purpose_check;
        ALTER TABLE public.mfa_challenges ADD CONSTRAINT mfa_challenges_purpose_check
            CHECK (purpose IN ('login', 'enroll', 'sensitive', 'factor_disable'));
        ALTER TABLE public.mfa_session_assurance DROP CONSTRAINT mfa_session_assurance_purpose_check;
        ALTER TABLE public.mfa_session_assurance ADD CONSTRAINT mfa_session_assurance_purpose_check
            CHECK (purpose IN ('sensitive', 'factor_disable'));
        ALTER TABLE public.auth_audit_events DROP CONSTRAINT ck_auth_event_type;
        ALTER TABLE public.auth_audit_events ADD CONSTRAINT ck_auth_event_type CHECK (
            event_type IN ('registration_attempt', 'login_attempt', 'mfa_attempt',
                'password_reset_attempt', 'mfa_recovery_attempt', 'session_issued',
                'session_revoked', 'sessions_revoked', 'password_verified',
                'login_mfa_required', 'session_rotated')
        );
    """)
