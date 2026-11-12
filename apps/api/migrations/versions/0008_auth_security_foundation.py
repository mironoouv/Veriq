"""Bind session issuance to verified credentials and add durable security events."""

import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None

FUNCTIONS = (
    (
        "veriq_auth_append_event(uuid, uuid, uuid, text, text, uuid, uuid, boolean)",
        "veriq_auth_events",
        "veriq_session_store",
    ),
    (
        "veriq_auth_append_attempt(uuid, uuid, uuid, text, text, uuid, uuid)",
        "veriq_auth_events",
        "veriq_api",
    ),
    ("veriq_auth_claim_notice(uuid)", "veriq_auth_events", "veriq_worker"),
    ("veriq_auth_ack_notice(uuid, uuid)", "veriq_auth_events", "veriq_worker"),
    (
        "veriq_auth_confirm(uuid, uuid, bigint, bytea, uuid, smallint)",
        "veriq_session_store",
        "veriq_credential_verifier",
    ),
    (
        "veriq_auth_issue(uuid, bytea, uuid, bytea, interval[], uuid, uuid, uuid)",
        "veriq_session_store",
        "veriq_session_issuer",
    ),
    (
        "veriq_auth_revoke(uuid, bytea, interval[], boolean, uuid, uuid, uuid)",
        "veriq_session_store",
        "veriq_api",
    ),
)


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "credential_version", sa.BigInteger(), nullable=False, server_default="1"
        ),
    )
    op.create_check_constraint(
        "ck_users_credential_version", "users", "credential_version > 0"
    )
    op.create_table(
        "auth_credential_proofs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("credential_version", sa.BigInteger(), nullable=False),
        sa.Column("proof_hash", sa.LargeBinary(), nullable=False),
        sa.Column("organization_id", sa.Uuid()),
        sa.Column("mfa_level", sa.SmallInteger(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("octet_length(proof_hash) = 32", name="ck_auth_proof_hash"),
        sa.CheckConstraint("mfa_level IN (0, 1)", name="ck_auth_proof_mfa"),
        sa.CheckConstraint("credential_version > 0", name="ck_auth_proof_version"),
    )
    op.create_index(
        "ix_auth_credential_proofs_user_id", "auth_credential_proofs", ["user_id"]
    )
    op.create_table(
        "auth_audit_events",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("request_id", sa.Uuid(), nullable=False),
        sa.Column("correlation_id", sa.Uuid(), nullable=False),
        sa.Column("event_type", sa.String(), nullable=False),
        sa.Column("result", sa.String(), nullable=False),
        sa.Column("actor_id", sa.Uuid()),
        sa.Column("target_id", sa.Uuid()),
        sa.Column("notify", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "event_type IN ('registration_attempt', 'login_attempt', 'mfa_attempt', "
            "'password_reset_attempt', 'mfa_recovery_attempt', 'session_issued', "
            "'session_revoked', 'sessions_revoked')",
            name="ck_auth_event_type",
        ),
        sa.CheckConstraint(
            "result IN ('succeeded', 'denied', 'failed')", name="ck_auth_event_result"
        ),
        sa.CheckConstraint(
            "NOT notify OR (target_id IS NOT NULL AND result = 'succeeded' AND event_type = 'sessions_revoked')",
            name="ck_auth_event_notify",
        ),
    )
    op.create_table(
        "notification_outbox",
        sa.Column(
            "event_id",
            sa.Uuid(),
            sa.ForeignKey("auth_audit_events.id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("claim_id", sa.Uuid()),
        sa.Column("lease_until", sa.DateTime(timezone=True)),
        sa.Column("delivered_at", sa.DateTime(timezone=True)),
        sa.Column("attempts", sa.BigInteger(), nullable=False, server_default="0"),
    )
    op.execute("""
        DO $$
        DECLARE name text;
        BEGIN
            FOREACH name IN ARRAY ARRAY['veriq_auth_events', 'veriq_credential_verifier'] LOOP
                IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = name) THEN
                    EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEROLE
                                    NOCREATEDB NOINHERIT NOREPLICATION NOBYPASSRLS', name);
                END IF;
                IF EXISTS (
                    SELECT FROM pg_catalog.pg_roles
                    WHERE rolname = name AND (
                        rolcanlogin OR rolsuper OR rolcreaterole OR rolcreatedb OR rolinherit OR
                        rolreplication OR rolbypassrls OR
                        oid IN (SELECT member FROM pg_catalog.pg_auth_members) OR
                        oid IN (SELECT roleid FROM pg_catalog.pg_auth_members)
                    )
                ) THEN
                    RAISE EXCEPTION 'Unsafe existing auth role: %', name;
                END IF;
            END LOOP;
        END;
        $$;

        GRANT USAGE ON SCHEMA public TO veriq_auth_events, veriq_credential_verifier;
        GRANT SELECT, INSERT ON public.auth_audit_events TO veriq_auth_events;
        GRANT SELECT, INSERT ON public.notification_outbox TO veriq_auth_events;
        GRANT UPDATE (claim_id, lease_until, delivered_at, attempts)
            ON public.notification_outbox TO veriq_auth_events;
        GRANT SELECT, INSERT ON public.auth_credential_proofs TO veriq_session_store;
        GRANT UPDATE (consumed_at) ON public.auth_credential_proofs TO veriq_session_store;
        GRANT SELECT (credential_version), UPDATE (credential_version)
            ON public.users TO veriq_session_store;

        REVOKE EXECUTE ON FUNCTION public.veriq_session_issue(uuid, uuid, bytea, uuid, smallint, interval[])
            FROM veriq_session_issuer;
        REVOKE EXECUTE ON FUNCTION public.veriq_session_revoke(uuid, bytea, interval[], boolean)
            FROM veriq_api;
    """)
    create_event_functions()
    create_credential_functions()
    for signature, owner, callers in FUNCTIONS:
        op.execute(f"ALTER FUNCTION public.{signature} OWNER TO {owner}")
        op.execute(f"REVOKE ALL ON FUNCTION public.{signature} FROM PUBLIC")
        op.execute(f"GRANT EXECUTE ON FUNCTION public.{signature} TO {callers}")


def create_event_functions() -> None:
    op.execute("""
        CREATE FUNCTION public.veriq_auth_append_event(
            p_event uuid, p_request uuid, p_correlation uuid, p_type text, p_result text,
            p_actor uuid, p_target uuid, p_notify boolean
        ) RETURNS boolean
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
        BEGIN
            INSERT INTO public.auth_audit_events (
                id, request_id, correlation_id, event_type, result, actor_id, target_id, notify
            ) VALUES (p_event, p_request, p_correlation, p_type, p_result, p_actor, p_target, p_notify)
            ON CONFLICT (id) DO NOTHING;
            IF NOT FOUND THEN
                RETURN EXISTS (
                    SELECT FROM public.auth_audit_events AS e WHERE e.id = p_event
                      AND (e.request_id, e.correlation_id, e.event_type, e.result, e.actor_id, e.target_id, e.notify)
                          IS NOT DISTINCT FROM
                          (p_request, p_correlation, p_type, p_result, p_actor, p_target, p_notify)
                );
            END IF;
            IF p_notify THEN
                INSERT INTO public.notification_outbox (event_id) VALUES (p_event);
            END IF;
            RETURN true;
        END;
        $$;

        CREATE FUNCTION public.veriq_auth_append_attempt(
            p_event uuid, p_request uuid, p_correlation uuid, p_type text, p_result text,
            p_actor uuid, p_target uuid
        ) RETURNS boolean
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
        BEGIN
            IF p_type NOT IN (
                'registration_attempt', 'login_attempt', 'mfa_attempt',
                'password_reset_attempt', 'mfa_recovery_attempt'
            ) THEN RETURN false; END IF;
            RETURN public.veriq_auth_append_event(
                p_event, p_request, p_correlation, p_type, p_result, p_actor, p_target, false
            );
        END;
        $$;

        CREATE FUNCTION public.veriq_auth_claim_notice(p_claim uuid)
        RETURNS TABLE (event_id uuid, target_id uuid, event_type text)
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
            WITH candidate AS (
                SELECT n.event_id
                FROM public.notification_outbox AS n
                JOIN public.auth_audit_events AS e ON e.id = n.event_id
                WHERE p_claim IS NOT NULL AND n.delivered_at IS NULL
                  AND (n.lease_until IS NULL OR n.lease_until <= clock_timestamp())
                ORDER BY e.created_at, n.event_id
                LIMIT 1 FOR UPDATE OF n SKIP LOCKED
            ), claimed AS (
                UPDATE public.notification_outbox AS n
                SET claim_id = p_claim, lease_until = clock_timestamp() + interval '30 seconds',
                    attempts = n.attempts + 1
                FROM candidate
                WHERE n.event_id = candidate.event_id
                RETURNING n.event_id
            )
            SELECT e.id, e.target_id, e.event_type::text FROM claimed
            JOIN public.auth_audit_events AS e ON e.id = claimed.event_id;
        $$;

        CREATE FUNCTION public.veriq_auth_ack_notice(p_event uuid, p_claim uuid) RETURNS boolean
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
        BEGIN
            UPDATE public.notification_outbox AS n
            SET delivered_at = clock_timestamp(), lease_until = NULL
            WHERE n.event_id = p_event AND n.claim_id = p_claim
              AND n.delivered_at IS NULL AND n.lease_until > clock_timestamp();
            IF FOUND THEN RETURN true; END IF;
            RETURN EXISTS (
                SELECT FROM public.notification_outbox AS n WHERE n.event_id = p_event
                  AND n.claim_id = p_claim AND n.delivered_at IS NOT NULL
            );
        END;
        $$;
    """)


def create_credential_functions() -> None:
    op.execute("""
        CREATE FUNCTION public.veriq_auth_confirm(
            p_id uuid, p_user uuid, p_version bigint, p_hash bytea, p_org uuid, p_mfa smallint
        ) RETURNS boolean
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
        BEGIN
            PERFORM pg_advisory_xact_lock(hashtextextended(p_user::text, 7007));
            INSERT INTO public.auth_credential_proofs (
                id, user_id, credential_version, proof_hash, organization_id, mfa_level, expires_at
            )
            SELECT p_id, u.id, u.credential_version, p_hash, p_org, p_mfa, clock_timestamp() + interval '60 seconds'
            FROM public.users AS u
            WHERE u.id = p_user AND u.credential_version = p_version AND u.disabled_at IS NULL;
            RETURN FOUND;
        END;
        $$;

        CREATE FUNCTION public.veriq_auth_issue(
            p_id uuid, p_hash bytea, p_session uuid, p_session_hash bytea, p_limits interval[],
            p_event uuid, p_request uuid, p_correlation uuid
        ) RETURNS boolean
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
        DECLARE account uuid; proof public.auth_credential_proofs%ROWTYPE;
        BEGIN
            SELECT p.user_id INTO account FROM public.auth_credential_proofs AS p
            WHERE p.id = p_id AND p.proof_hash = p_hash;
            IF NOT FOUND THEN RETURN false; END IF;
            PERFORM pg_advisory_xact_lock(hashtextextended(account::text, 7007));
            SELECT p.* INTO proof FROM public.auth_credential_proofs AS p
            JOIN public.users AS u ON u.id = p.user_id
            WHERE p.id = p_id AND p.proof_hash = p_hash AND p.consumed_at IS NULL
              AND p.expires_at > clock_timestamp()
              AND u.credential_version = p.credential_version AND u.disabled_at IS NULL
            FOR UPDATE OF p;
            IF NOT FOUND OR NOT public.veriq_session_issue(
                p_session, proof.user_id, p_session_hash, proof.organization_id, proof.mfa_level, p_limits
            ) THEN RETURN false; END IF;
            UPDATE public.auth_credential_proofs SET consumed_at = clock_timestamp() WHERE id = p_id;
            IF NOT public.veriq_auth_append_event(
                p_event, p_request, p_correlation, 'session_issued', 'succeeded', account, account, false
            ) THEN RAISE EXCEPTION 'Conflicting auth event ID'; END IF;
            RETURN true;
        END;
        $$;

        CREATE FUNCTION public.veriq_auth_revoke(
            p_id uuid, p_hash bytea, p_limits interval[], p_all boolean,
            p_event uuid, p_request uuid, p_correlation uuid
        ) RETURNS bigint
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
        DECLARE account uuid; affected bigint;
        BEGIN
            SELECT s.user_id INTO account FROM public.auth_sessions AS s
            WHERE s.id = p_id AND s.token_hash = p_hash;
            IF NOT FOUND THEN RETURN 0; END IF;
            IF p_all THEN
                PERFORM pg_advisory_xact_lock(hashtextextended(account::text, 7007));
            END IF;
            affected := public.veriq_session_revoke(p_id, p_hash, p_limits, p_all);
            IF affected > 0 THEN
                IF p_all THEN
                    UPDATE public.users SET credential_version = credential_version + 1 WHERE id = account;
                END IF;
                IF NOT public.veriq_auth_append_event(
                    p_event, p_request, p_correlation,
                    CASE WHEN p_all THEN 'sessions_revoked' ELSE 'session_revoked' END,
                    'succeeded', account, account, p_all
                ) THEN RAISE EXCEPTION 'Conflicting auth event ID'; END IF;
            END IF;
            RETURN affected;
        END;
        $$;
    """)


def downgrade() -> None:
    op.execute("""
        LOCK TABLE public.users, public.auth_credential_proofs, public.auth_audit_events,
            public.notification_outbox IN ACCESS EXCLUSIVE MODE;
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM public.auth_credential_proofs)
               OR EXISTS (SELECT 1 FROM public.auth_audit_events)
               OR EXISTS (SELECT 1 FROM public.users WHERE credential_version <> 1) THEN
                RAISE EXCEPTION 'Downgrade would remove Auth history';
            END IF;
        END;
        $$;
    """)
    for signature, _, _ in reversed(FUNCTIONS):
        op.execute(f"DROP FUNCTION public.{signature}")
    op.execute("""
        GRANT EXECUTE ON FUNCTION public.veriq_session_issue(uuid, uuid, bytea, uuid, smallint, interval[])
            TO veriq_session_issuer;
        GRANT EXECUTE ON FUNCTION public.veriq_session_revoke(uuid, bytea, interval[], boolean)
            TO veriq_api;
        REVOKE SELECT (credential_version), UPDATE (credential_version)
            ON public.users FROM veriq_session_store;
        REVOKE USAGE ON SCHEMA public FROM veriq_auth_events, veriq_credential_verifier;
    """)
    op.drop_table("notification_outbox")
    op.drop_table("auth_audit_events")
    op.drop_table("auth_credential_proofs")
    op.drop_constraint("ck_users_credential_version", "users", type_="check")
    op.drop_column("users", "credential_version")
