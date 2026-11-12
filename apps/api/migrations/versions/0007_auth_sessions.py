"""Store session verifiers behind narrowly scoped database functions."""

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None

READ_POLICIES = {
    "organization_memberships": "id, organization_id, user_id, grant_epoch",
    "membership_roles": "organization_id, membership_id, role_id, grant_epoch",
    "organization_roles": "organization_id, id, code",
}
FUNCTIONS = {
    "veriq_session_limits(uuid, uuid, smallint, interval[])": None,
    "veriq_session_issue(uuid, uuid, bytea, uuid, smallint, interval[])": "veriq_session_issuer",
    "veriq_session_use(uuid, bytea, interval[], uuid, bytea, uuid)": "veriq_api",
    "veriq_session_current(uuid, bytea, uuid, uuid, interval[])": "veriq_api",
    "veriq_session_revoke(uuid, bytea, interval[], boolean)": "veriq_api",
}


def upgrade() -> None:
    op.create_table(
        "auth_sessions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("token_hash", sa.LargeBinary(), nullable=False, unique=True),
        sa.Column("organization_id", sa.Uuid()),
        sa.Column("grant_epoch", sa.BigInteger()),
        sa.Column("mfa_level", sa.SmallInteger(), nullable=False),
        sa.Column("authenticated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("idle_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("absolute_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("revoke_reason", sa.String()),
        sa.ForeignKeyConstraint(
            ["organization_id", "user_id"],
            [
                "organization_memberships.organization_id",
                "organization_memberships.user_id",
            ],
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "octet_length(token_hash) = 32", name="ck_auth_sessions_hash"
        ),
        sa.CheckConstraint("mfa_level IN (0, 1)", name="ck_auth_sessions_mfa"),
        sa.CheckConstraint(
            "(organization_id IS NULL AND grant_epoch IS NULL) OR "
            "(organization_id IS NOT NULL AND grant_epoch IS NOT NULL AND grant_epoch >= 0)",
            name="ck_auth_sessions_selection",
        ),
        sa.CheckConstraint(
            "authenticated_at <= created_at AND created_at <= last_seen_at "
            "AND last_seen_at < idle_expires_at AND idle_expires_at <= absolute_expires_at",
            name="ck_auth_sessions_lifetime",
        ),
        sa.CheckConstraint(
            "(revoked_at IS NULL AND revoke_reason IS NULL) OR "
            "(revoked_at IS NOT NULL AND revoke_reason IS NOT NULL "
            "AND revoke_reason IN ('logout', 'account_logout', 'rotated', 'organization_changed'))",
            name="ck_auth_sessions_revocation",
        ),
    )
    op.create_index("ix_auth_sessions_user_id", "auth_sessions", ["user_id"])
    op.create_index(
        "ix_auth_sessions_membership", "auth_sessions", ["organization_id", "user_id"]
    )
    op.execute("""
        DO $$
        DECLARE name text;
        BEGIN
            FOREACH name IN ARRAY ARRAY['veriq_session_store', 'veriq_session_issuer'] LOOP
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
                    RAISE EXCEPTION 'Unsafe existing session role: %', name;
                END IF;
            END LOOP;
        END;
        $$;

        GRANT USAGE ON SCHEMA public TO veriq_session_store, veriq_session_issuer;
        GRANT SELECT, INSERT ON public.auth_sessions TO veriq_session_store;
        GRANT UPDATE (last_seen_at, idle_expires_at, absolute_expires_at, revoked_at, revoke_reason)
            ON public.auth_sessions TO veriq_session_store;
        GRANT SELECT (id, disabled_at) ON public.users TO veriq_session_store;
        GRANT SELECT (id, code) ON public.platform_roles TO veriq_session_store;
        GRANT SELECT (user_id, role_id) ON public.platform_role_assignments TO veriq_session_store;
        GRANT EXECUTE ON FUNCTION public.veriq_active_membership(uuid, text) TO veriq_session_store;
    """)
    for table, columns in READ_POLICIES.items():
        op.execute(f"GRANT SELECT ({columns}) ON public.{table} TO veriq_session_store")
        op.execute(f"""
            CREATE POLICY session_store_lookup ON public.{table}
                FOR SELECT TO veriq_session_store USING (true)
        """)
    create_session_functions()
    for signature, caller in FUNCTIONS.items():
        op.execute(f"ALTER FUNCTION public.{signature} OWNER TO veriq_session_store")
        op.execute(f"REVOKE ALL ON FUNCTION public.{signature} FROM PUBLIC")
        if caller:
            op.execute(f"GRANT EXECUTE ON FUNCTION public.{signature} TO {caller}")


def create_session_functions() -> None:
    op.execute("""
        CREATE FUNCTION public.veriq_session_limits(
            p_user uuid, p_org uuid, p_mfa smallint, p_limits interval[]
        ) RETURNS TABLE (epoch bigint, idle_limit interval, absolute_limit interval)
        LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
            WITH eligible AS (
                SELECT membership.grant_epoch, (
                    EXISTS (
                        SELECT 1 FROM public.platform_role_assignments AS assignment
                        JOIN public.platform_roles AS role ON role.id = assignment.role_id
                        WHERE assignment.user_id = p_user AND role.code = 'superadmin'
                    )
                    OR EXISTS (
                        SELECT 1 FROM public.membership_roles AS assignment
                        JOIN public.organization_roles AS role
                          ON role.organization_id = assignment.organization_id AND role.id = assignment.role_id
                        WHERE assignment.organization_id = p_org AND assignment.membership_id = membership.id
                          AND assignment.grant_epoch = membership.grant_epoch
                          AND role.code IN ('org_admin', 'technician')
                    )
                ) AS privileged
                FROM public.users AS account
                LEFT JOIN public.organization_memberships AS membership
                  ON membership.user_id = account.id AND membership.organization_id = p_org
                WHERE account.id = p_user AND account.disabled_at IS NULL
                  AND (p_org IS NULL OR public.veriq_active_membership(p_org, p_user::text))
            )
            SELECT grant_epoch, p_limits[CASE WHEN privileged THEN 1 ELSE 3 END],
                   p_limits[CASE WHEN privileged THEN 2 ELSE 4 END]
            FROM eligible WHERE NOT privileged OR p_mfa = 1;
        $$;

        CREATE FUNCTION public.veriq_session_issue(
            p_id uuid, p_user uuid, p_hash bytea, p_org uuid, p_mfa smallint, p_limits interval[]
        ) RETURNS boolean
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
        DECLARE profile record; tick timestamptz;
        BEGIN
            PERFORM pg_advisory_xact_lock(hashtextextended(p_user::text, 7007));
            SELECT * INTO profile FROM public.veriq_session_limits(p_user, p_org, p_mfa, p_limits);
            IF NOT FOUND THEN RETURN false; END IF;
            tick := clock_timestamp();
            INSERT INTO public.auth_sessions (
                id, user_id, token_hash, organization_id, grant_epoch, mfa_level,
                authenticated_at, created_at, last_seen_at, idle_expires_at, absolute_expires_at
            ) VALUES (
                p_id, p_user, p_hash, p_org, profile.epoch, p_mfa,
                tick, tick, tick, tick + profile.idle_limit, tick + profile.absolute_limit
            );
            RETURN true;
        END;
        $$;

        CREATE FUNCTION public.veriq_session_use(
            p_id uuid, p_hash bytea, p_limits interval[],
            p_next_id uuid, p_next_hash bytea, p_target uuid
        ) RETURNS TABLE (user_id uuid, organization_id uuid, mfa_level smallint)
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
        DECLARE
            current_session public.auth_sessions%ROWTYPE;
            account uuid;
            profile record;
            tick timestamptz;
            deadline timestamptz;
        BEGIN
            IF p_next_id IS NOT NULL THEN
                SELECT s.user_id INTO account FROM public.auth_sessions AS s
                WHERE s.id = p_id AND s.token_hash = p_hash;
                IF NOT FOUND THEN RETURN; END IF;
                PERFORM pg_advisory_xact_lock(hashtextextended(account::text, 7007));
            END IF;

            SELECT s.* INTO current_session FROM public.auth_sessions AS s
            WHERE s.id = p_id AND s.token_hash = p_hash FOR UPDATE;
            IF NOT FOUND OR current_session.revoked_at IS NOT NULL THEN RETURN; END IF;
            SELECT * INTO profile FROM public.veriq_session_limits(
                current_session.user_id, current_session.organization_id, current_session.mfa_level, p_limits
            );
            IF NOT FOUND OR profile.epoch IS DISTINCT FROM current_session.grant_epoch THEN RETURN; END IF;
            tick := greatest(clock_timestamp(), current_session.last_seen_at);
            deadline := least(current_session.absolute_expires_at,
                              current_session.authenticated_at + profile.absolute_limit);
            IF tick >= least(deadline, current_session.idle_expires_at,
                             current_session.last_seen_at + profile.idle_limit) THEN RETURN; END IF;

            IF p_next_id IS NULL THEN
                UPDATE public.auth_sessions
                SET last_seen_at = tick,
                    idle_expires_at = least(deadline, tick + profile.idle_limit),
                    absolute_expires_at = deadline
                WHERE id = p_id;
                RETURN QUERY SELECT current_session.user_id, current_session.organization_id,
                                    current_session.mfa_level;
                RETURN;
            END IF;

            SELECT * INTO profile FROM public.veriq_session_limits(
                current_session.user_id, p_target, current_session.mfa_level, p_limits
            );
            IF NOT FOUND THEN RETURN; END IF;
            deadline := least(deadline, current_session.authenticated_at + profile.absolute_limit);
            IF tick >= deadline THEN RETURN; END IF;
            UPDATE public.auth_sessions
            SET revoked_at = tick, revoke_reason = CASE
                WHEN p_target IS DISTINCT FROM current_session.organization_id THEN 'organization_changed'
                ELSE 'rotated'
            END
            WHERE id = p_id;
            INSERT INTO public.auth_sessions (
                id, user_id, token_hash, organization_id, grant_epoch, mfa_level,
                authenticated_at, created_at, last_seen_at, idle_expires_at, absolute_expires_at
            ) VALUES (
                p_next_id, current_session.user_id, p_next_hash, p_target, profile.epoch, current_session.mfa_level,
                current_session.authenticated_at, tick, tick, least(deadline, tick + profile.idle_limit), deadline
            );
            RETURN QUERY SELECT current_session.user_id, p_target, current_session.mfa_level;
        END;
        $$;

        CREATE FUNCTION public.veriq_session_current(
            p_id uuid, p_hash bytea, p_user uuid, p_org uuid, p_limits interval[]
        ) RETURNS boolean
        LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
            SELECT EXISTS (
                SELECT 1 FROM public.auth_sessions AS s
                CROSS JOIN LATERAL public.veriq_session_limits(
                    s.user_id, s.organization_id, s.mfa_level, p_limits
                ) AS profile
                WHERE s.id = p_id AND s.token_hash = p_hash AND s.user_id = p_user
                  AND s.organization_id IS NOT DISTINCT FROM p_org
                  AND s.revoked_at IS NULL AND s.grant_epoch IS NOT DISTINCT FROM profile.epoch
                  AND statement_timestamp() < least(
                      s.idle_expires_at, s.absolute_expires_at, s.last_seen_at + profile.idle_limit,
                      s.authenticated_at + profile.absolute_limit
                  )
            );
        $$;

        CREATE FUNCTION public.veriq_session_revoke(
            p_id uuid, p_hash bytea, p_limits interval[], p_all boolean
        ) RETURNS bigint
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
        DECLARE account uuid; affected bigint;
        BEGIN
            IF p_all THEN
                SELECT s.user_id INTO account FROM public.auth_sessions AS s
                WHERE s.id = p_id AND s.token_hash = p_hash;
                IF NOT FOUND THEN RETURN 0; END IF;
                PERFORM pg_advisory_xact_lock(hashtextextended(account::text, 7007));
                PERFORM 1 FROM public.veriq_session_use(p_id, p_hash, p_limits, NULL, NULL, NULL);
                IF NOT FOUND THEN RETURN 0; END IF;
                UPDATE public.auth_sessions AS s
                SET revoked_at = greatest(clock_timestamp(), s.last_seen_at), revoke_reason = 'account_logout'
                WHERE s.user_id = account AND s.revoked_at IS NULL;
            ELSE
                UPDATE public.auth_sessions AS s
                SET revoked_at = greatest(clock_timestamp(), s.last_seen_at), revoke_reason = 'logout'
                WHERE s.id = p_id AND s.token_hash = p_hash AND s.revoked_at IS NULL;
            END IF;
            GET DIAGNOSTICS affected = ROW_COUNT;
            RETURN affected;
        END;
        $$;
    """)


def downgrade() -> None:
    op.execute("""
        LOCK TABLE public.auth_sessions IN ACCESS EXCLUSIVE MODE;
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM public.auth_sessions) THEN
                RAISE EXCEPTION 'Downgrade requires an empty auth_sessions table';
            END IF;
        END;
        $$;
    """)
    for signature in reversed(FUNCTIONS):
        op.execute(f"DROP FUNCTION public.{signature}")
    for table, columns in READ_POLICIES.items():
        op.execute(f"DROP POLICY session_store_lookup ON public.{table}")
        op.execute(
            f"REVOKE SELECT ({columns}) ON public.{table} FROM veriq_session_store"
        )
    op.execute("""
        REVOKE SELECT (id, disabled_at) ON public.users FROM veriq_session_store;
        REVOKE SELECT (id, code) ON public.platform_roles FROM veriq_session_store;
        REVOKE SELECT (user_id, role_id) ON public.platform_role_assignments FROM veriq_session_store;
        REVOKE EXECUTE ON FUNCTION public.veriq_active_membership(uuid, text) FROM veriq_session_store;
        REVOKE USAGE ON SCHEMA public FROM veriq_session_store, veriq_session_issuer;
    """)
    op.drop_table("auth_sessions")
