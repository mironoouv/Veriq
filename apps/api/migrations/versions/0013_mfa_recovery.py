"""Independent MFA recovery state and restricted database transitions."""

from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None

AUTHORITY_TABLES = (
    "organizations",
    "organization_memberships",
    "organization_roles",
    "organization_role_permissions",
    "membership_roles",
    "platform_roles",
    "platform_role_permissions",
    "platform_role_assignments",
    "mfa_recovery_sources",
    "organization_mfa_policies",
)


def upgrade() -> None:
    op.execute("""
        ALTER TABLE public.platform_roles DROP CONSTRAINT ck_platform_roles_code;
        ALTER TABLE public.platform_roles ADD CONSTRAINT ck_platform_roles_code CHECK (
            code IN ('superadmin','mfa_recovery_approver','mfa_recovery_verifier')
        );
        INSERT INTO public.permissions(scope,code) VALUES ('organization','mfa.recovery.verify'),
            ('platform','mfa.recovery.verify'),('platform','mfa.recovery.approve') ON CONFLICT DO NOTHING;
        INSERT INTO public.platform_roles(id,code) VALUES
            (gen_random_uuid(),'mfa_recovery_approver'),(gen_random_uuid(),'mfa_recovery_verifier');
        INSERT INTO public.platform_role_permissions(role_id,permission_code)
            SELECT id,CASE WHEN code='mfa_recovery_approver' THEN 'mfa.recovery.approve' ELSE 'mfa.recovery.verify' END
            FROM public.platform_roles WHERE code IN ('mfa_recovery_approver','mfa_recovery_verifier');
        CREATE TABLE public.mfa_recovery_sources (
            user_id uuid PRIMARY KEY REFERENCES public.users(id),
            organization_id uuid REFERENCES public.organizations(id),
            source_id uuid NOT NULL UNIQUE,
            registered_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            revoked_at timestamptz
        );
        CREATE TABLE public.mfa_recovery_requests (
            id uuid PRIMARY KEY,
            user_id uuid NOT NULL REFERENCES public.users(id),
            organization_id uuid REFERENCES public.organizations(id),
            source_id uuid NOT NULL,
            credential_version bigint NOT NULL,
            state text NOT NULL CHECK (state IN ('pending_identity','pending_review','approved_waiting',
                'disputed','enrollment_authorized','completed','expired','recovery_locked')),
            created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            expires_at timestamptz NOT NULL DEFAULT clock_timestamp() + interval '7 days',
            reviewer uuid REFERENCES public.users(id),
            approver uuid REFERENCES public.users(id),
            reviewer_epoch bigint,
            reviewer_version bigint,
            approver_version bigint,
            authority_version bigint,
            approved_at timestamptz,
            approved_event uuid REFERENCES public.auth_audit_events(id),
            CHECK (reviewer IS DISTINCT FROM user_id AND approver IS DISTINCT FROM user_id),
            CHECK (reviewer IS NULL OR approver IS NULL OR reviewer <> approver)
        );
        CREATE UNIQUE INDEX ix_mfa_recovery_active_user ON public.mfa_recovery_requests(user_id)
            WHERE state NOT IN ('completed','expired','recovery_locked');
        CREATE TABLE public.mfa_recovery_actions (
            id uuid PRIMARY KEY,
            request_id uuid NOT NULL REFERENCES public.mfa_recovery_requests(id),
            actor_id uuid NOT NULL REFERENCES public.users(id),
            action text NOT NULL
        );
        CREATE TABLE public.mfa_recovery_holds (
            user_id uuid PRIMARY KEY REFERENCES public.users(id),
            request_id uuid NOT NULL UNIQUE REFERENCES public.mfa_recovery_requests(id)
        );
        CREATE TABLE public.mfa_recovery_enrollments (
            request_id uuid PRIMARY KEY REFERENCES public.mfa_recovery_requests(id),
            digest bytea NOT NULL CHECK (octet_length(digest)=32),
            credential_version bigint NOT NULL,
            expires_at timestamptz NOT NULL,
            consumed_at timestamptz,
            attempts smallint NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
            factor_id uuid,
            key_id text,
            ciphertext bytea,
            binding bytea
        );
        CREATE TABLE public.mfa_recovery_authority (
            id boolean PRIMARY KEY CHECK (id),
            revision bigint NOT NULL
        );
        INSERT INTO public.mfa_recovery_authority VALUES (true,1);

        ALTER TABLE public.mfa_recovery_requests ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.mfa_recovery_requests FORCE ROW LEVEL SECURITY;
        CREATE POLICY mfa_recovery_internal ON public.mfa_recovery_requests
            TO veriq_session_store USING (true) WITH CHECK (true);
        GRANT SELECT ON public.mfa_recovery_sources TO veriq_session_store;
        GRANT SELECT, INSERT, UPDATE ON public.mfa_recovery_requests, public.mfa_recovery_actions,
            public.mfa_recovery_enrollments TO veriq_session_store;
        GRANT SELECT, INSERT, UPDATE, DELETE ON public.mfa_recovery_holds TO veriq_session_store;
        GRANT SELECT, UPDATE ON public.mfa_recovery_authority TO veriq_session_store;
        GRANT DELETE ON public.mfa_factors TO veriq_session_store;
        GRANT SELECT (organization_id, role_id, permission_code) ON public.organization_role_permissions TO veriq_session_store;
        CREATE POLICY recovery_permission_lookup ON public.organization_role_permissions
            FOR SELECT TO veriq_session_store USING (true);
        GRANT SELECT (role_id, permission_code) ON public.platform_role_permissions TO veriq_session_store;


        ALTER TABLE public.mfa_challenges ADD COLUMN resource_id uuid;
        ALTER TABLE public.mfa_session_assurance ADD COLUMN resource_id uuid;
        ALTER TABLE public.mfa_challenges DROP CONSTRAINT mfa_challenges_purpose_check;
        ALTER TABLE public.mfa_challenges ADD CONSTRAINT mfa_challenges_purpose_check
            CHECK (purpose IN ('login','enroll','sensitive','factor_disable','password_change','mfa_recovery_review','mfa_recovery_release')
                AND ((resource_id IS NOT NULL) = (purpose IN ('mfa_recovery_review','mfa_recovery_release'))));
        ALTER TABLE public.mfa_session_assurance DROP CONSTRAINT mfa_session_assurance_purpose_check;
        ALTER TABLE public.mfa_session_assurance ADD CONSTRAINT mfa_session_assurance_purpose_check
            CHECK (purpose IN ('sensitive','factor_disable','password_change','mfa_recovery_review','mfa_recovery_release')
                AND ((resource_id IS NOT NULL) = (purpose IN ('mfa_recovery_review','mfa_recovery_release'))));
        ALTER TABLE public.auth_audit_events DROP CONSTRAINT ck_auth_event_type;
        ALTER TABLE public.auth_audit_events ADD CONSTRAINT ck_auth_event_type CHECK (
            event_type IN ('registration_attempt','login_attempt','mfa_attempt','password_reset_attempt',
                'mfa_recovery_attempt','session_issued','session_revoked','sessions_revoked','password_verified',
                'login_mfa_required','session_rotated','password_changed','password_reset',
                'mfa_recovery_started','mfa_recovery_reviewed','mfa_recovery_voted','mfa_recovery_approved',
                'mfa_recovery_disputed','mfa_recovery_reopened','mfa_recovery_released','mfa_recovery_completed')
        );
        ALTER TABLE public.auth_audit_events DROP CONSTRAINT ck_auth_event_notify;
        ALTER TABLE public.auth_audit_events ADD CONSTRAINT ck_auth_event_notify CHECK (
            NOT notify OR (target_id IS NOT NULL AND result='succeeded' AND event_type IN (
                'sessions_revoked','password_changed','password_reset','mfa_recovery_started',
                'mfa_recovery_approved','mfa_recovery_disputed','mfa_recovery_released','mfa_recovery_completed'))
        );

        CREATE FUNCTION public.veriq_recovery_authority_changed() RETURNS trigger
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
        BEGIN
            PERFORM pg_advisory_xact_lock(670013::bigint);
            UPDATE public.mfa_recovery_authority SET revision=revision+1 WHERE id;
            RETURN NULL;
        END;
        $$;
        ALTER FUNCTION public.veriq_recovery_authority_changed() OWNER TO veriq_session_store;
        REVOKE ALL ON FUNCTION public.veriq_recovery_authority_changed() FROM PUBLIC;

        ALTER FUNCTION public.veriq_mfa_account(uuid,bigint) RENAME TO veriq_pre_recovery_mfa_account;
        REVOKE EXECUTE ON FUNCTION public.veriq_pre_recovery_mfa_account(uuid,bigint) FROM veriq_mfa_verifier;
        CREATE FUNCTION public.veriq_mfa_account(p_user uuid,p_version bigint)
        RETURNS bigint LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
            SELECT public.veriq_pre_recovery_mfa_account(p_user,p_version)
            WHERE NOT EXISTS (SELECT FROM public.mfa_recovery_holds WHERE user_id=p_user)
        $$;
        ALTER FUNCTION public.veriq_mfa_account(uuid,bigint) OWNER TO veriq_session_store;
        REVOKE ALL ON FUNCTION public.veriq_mfa_account(uuid,bigint) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION public.veriq_mfa_account(uuid,bigint) TO veriq_mfa_verifier;

        ALTER FUNCTION public.veriq_session_limits(uuid,uuid,smallint,interval[])
            RENAME TO veriq_pre_recovery_session_limits;
        CREATE FUNCTION public.veriq_session_limits(
            p_user uuid,p_org uuid,p_mfa smallint,p_limits interval[]
        ) RETURNS TABLE (epoch bigint,idle_limit interval,absolute_limit interval)
        LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
            SELECT s.* FROM public.veriq_pre_recovery_session_limits(p_user,p_org,p_mfa,p_limits) AS s
            WHERE NOT EXISTS (SELECT FROM public.mfa_recovery_holds WHERE user_id=p_user)
        $$;
        ALTER FUNCTION public.veriq_session_limits(uuid,uuid,smallint,interval[]) OWNER TO veriq_session_store;
        REVOKE ALL ON FUNCTION public.veriq_session_limits(uuid,uuid,smallint,interval[]) FROM PUBLIC;
    """)
    for table in AUTHORITY_TABLES:
        op.execute(f"""CREATE TRIGGER mfa_recovery_authority_changed
            BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON public.{table}
            FOR EACH STATEMENT EXECUTE FUNCTION public.veriq_recovery_authority_changed()""")
    create_workflow()
    create_enrollment()
    extend_notices()


FUNCTIONS = {
    "veriq_recovery_start(uuid,bytea,uuid,uuid,uuid)": "veriq_api",
    "veriq_recovery_transition(uuid,bytea,interval[],uuid,text,uuid,bytea,uuid,uuid)": "veriq_api",
    "veriq_recovery_enrollment(uuid,bytea,bytea,uuid,bytea,uuid,text,bytea)": "veriq_mfa_verifier",
    "veriq_recovery_complete(uuid,bytea,bytea,bigint,bytea[],bytea[],uuid,uuid)": "veriq_mfa_verifier",
    "veriq_recovery_reject(uuid,bytea,bytea,uuid,uuid)": "veriq_mfa_verifier",
}


def install(signature: str, callers: str | None = None) -> None:
    op.execute(f"ALTER FUNCTION public.{signature} OWNER TO veriq_session_store")
    op.execute(f"REVOKE ALL ON FUNCTION public.{signature} FROM PUBLIC")
    if callers is not None:
        op.execute(f"GRANT EXECUTE ON FUNCTION public.{signature} TO {callers}")


def create_workflow() -> None:
    op.execute("""
        CREATE FUNCTION public.veriq_recovery_permission(p_user uuid,p_org uuid,p_code text)
        RETURNS boolean LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
            SELECT EXISTS (SELECT FROM public.users WHERE id=p_user AND disabled_at IS NULL)
            AND CASE WHEN p_org IS NULL THEN EXISTS (
                SELECT FROM public.platform_role_assignments AS a JOIN public.platform_role_permissions AS p
                    ON p.role_id=a.role_id WHERE a.user_id=p_user AND p.permission_code=p_code
            ) ELSE public.veriq_active_membership(p_org,p_user::text) AND EXISTS (
                SELECT FROM public.organization_memberships AS m JOIN public.membership_roles AS a
                    ON a.organization_id=m.organization_id AND a.membership_id=m.id AND a.grant_epoch=m.grant_epoch
                JOIN public.organization_role_permissions AS p
                    ON p.organization_id=a.organization_id AND p.role_id=a.role_id
                WHERE m.user_id=p_user AND m.organization_id=p_org AND p.permission_code=p_code
            ) END
        $$;

        CREATE FUNCTION public.veriq_recovery_superadmin(p_user uuid)
        RETURNS boolean LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
            SELECT EXISTS (SELECT FROM public.platform_role_assignments a JOIN public.platform_roles r
                ON r.id=a.role_id WHERE a.user_id=p_user AND r.code='superadmin')
        $$;

        CREATE FUNCTION public.veriq_recovery_start(p_proof uuid,p_digest bytea,p_event uuid,p_request uuid,p_correlation uuid)
        RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
        DECLARE account uuid; source public.mfa_recovery_sources%ROWTYPE; version bigint; case_id uuid;
        BEGIN
            SELECT user_id INTO account FROM public.auth_credential_proofs WHERE id=p_proof AND proof_hash=p_digest;
            IF NOT FOUND THEN RETURN; END IF;
            PERFORM pg_advisory_xact_lock(hashtextextended(account::text,7007));
            PERFORM pg_advisory_xact_lock_shared(670013::bigint);
            SELECT p.credential_version INTO version FROM public.auth_credential_proofs p JOIN public.users u ON u.id=p.user_id
            WHERE p.id=p_proof AND p.proof_hash=p_digest AND p.mfa_level=0 AND p.consumed_at IS NULL
                AND p.expires_at>clock_timestamp() AND p.credential_version=u.credential_version
                AND u.disabled_at IS NULL AND u.email_verified_at IS NOT NULL;
            IF NOT FOUND OR public.veriq_recovery_superadmin(account) THEN RETURN; END IF;
            UPDATE public.auth_credential_proofs SET consumed_at=clock_timestamp() WHERE id=p_proof;
            SELECT * INTO source FROM public.mfa_recovery_sources WHERE user_id=account AND revoked_at IS NULL
                AND registered_at<clock_timestamp();
            IF NOT FOUND OR (source.organization_id IS NOT NULL AND NOT public.veriq_active_membership(
                source.organization_id,account::text
            )) OR NOT EXISTS (SELECT FROM public.mfa_factors WHERE user_id=account AND confirmed_at IS NOT NULL)
            THEN RETURN; END IF;
            UPDATE public.mfa_recovery_requests SET state='expired' WHERE user_id=account
                AND state IN ('pending_identity','pending_review','approved_waiting','disputed') AND expires_at<=clock_timestamp();
            INSERT INTO public.mfa_recovery_requests (id,user_id,organization_id,source_id,credential_version,state)
            VALUES (p_event,account,source.organization_id,source.source_id,version,'pending_identity')
            ON CONFLICT DO NOTHING RETURNING id INTO case_id;
            IF case_id IS NOT NULL THEN
                IF NOT public.veriq_auth_append_event(
                    p_event,p_request,p_correlation,'mfa_recovery_started','succeeded',NULL,account,true
                ) THEN RAISE EXCEPTION 'Conflicting recovery event'; END IF;
            END IF;
        END;
        $$;

        CREATE FUNCTION public.veriq_recovery_transition(
            p_session uuid,p_digest bytea,p_limits interval[],p_case uuid,p_action text,
            p_event uuid,p_capability bytea,p_correlation uuid,p_source uuid
        ) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
        DECLARE actor uuid; actor_org uuid; account uuid; staff record; item public.mfa_recovery_requests%ROWTYPE;
            original_reviewer uuid; original_approver uuid;
            current_version bigint; event_type text; action_purpose text; scope uuid; permission text;
        BEGIN
            SELECT user_id,organization_id INTO actor,actor_org FROM public.auth_sessions
            WHERE id=p_session AND token_hash=p_digest;
            SELECT user_id,reviewer,approver INTO account,original_reviewer,original_approver
            FROM public.mfa_recovery_requests WHERE id=p_case;
            IF actor IS NULL OR account IS NULL OR actor=account THEN RETURN 'denied'; END IF;
            FOR staff IN SELECT DISTINCT key FROM (
                SELECT hashtextextended(actor::text,7007) AS key
                UNION ALL SELECT hashtextextended(account::text,7007)
                UNION ALL SELECT hashtextextended(original_reviewer::text,7007)
                UNION ALL SELECT hashtextextended(original_approver::text,7007)
            ) AS keys WHERE key IS NOT NULL ORDER BY key LOOP
                PERFORM pg_advisory_xact_lock(staff.key);
            END LOOP;
            PERFORM pg_advisory_xact_lock_shared(670013::bigint);
            SELECT * INTO item FROM public.mfa_recovery_requests WHERE id=p_case FOR UPDATE;
            IF NOT FOUND OR item.reviewer IS DISTINCT FROM original_reviewer
                OR item.approver IS DISTINCT FROM original_approver
                OR (item.expires_at<=clock_timestamp() AND NOT (
                p_action IN ('reopen','dispute') AND item.state IN ('enrollment_authorized','recovery_locked')
            ))
                OR public.veriq_recovery_superadmin(account)
                OR NOT EXISTS (SELECT FROM public.mfa_recovery_sources AS s WHERE s.user_id=account
                    AND s.source_id=item.source_id AND s.organization_id IS NOT DISTINCT FROM item.organization_id
                    AND s.registered_at<item.created_at AND s.revoked_at IS NULL)
                OR (item.organization_id IS NOT NULL AND NOT public.veriq_active_membership(item.organization_id,account::text))
                OR NOT EXISTS (SELECT FROM public.users WHERE id=account AND disabled_at IS NULL)
            THEN RETURN 'denied'; END IF;

            IF p_action IN ('verify','dispute','reopen') THEN
                scope:=item.organization_id;
                permission:='mfa.recovery.verify';
            ELSIF p_action IN ('approve','release') THEN
                scope:=NULL;
                permission:='mfa.recovery.approve';
            ELSE RETURN 'denied'; END IF;
            action_purpose:=CASE WHEN p_action='release' THEN 'mfa_recovery_release' ELSE 'mfa_recovery_review' END;
            IF actor_org IS DISTINCT FROM scope OR NOT public.veriq_recovery_permission(actor,scope,permission)
                OR NOT public.veriq_mfa_fresh(p_session,p_digest,p_limits,action_purpose,interval '5 minutes')
                OR NOT EXISTS (SELECT FROM public.mfa_session_assurance WHERE session_id=p_session AND resource_id=p_case)
            THEN RETURN 'denied'; END IF;
            IF EXISTS (SELECT FROM public.mfa_recovery_actions WHERE id=p_event AND request_id=p_case
                AND actor_id=actor AND action=p_action) THEN RETURN 'replayed'; END IF;
            IF EXISTS (SELECT FROM public.mfa_recovery_actions WHERE id=p_event) THEN RETURN 'denied'; END IF;
            IF p_action NOT IN ('reopen','dispute') AND NOT EXISTS (
                SELECT FROM public.users WHERE id=account AND credential_version=item.credential_version
            ) THEN RETURN 'denied'; END IF;

            SELECT revision INTO current_version FROM public.mfa_recovery_authority WHERE id;
            IF p_action='dispute' AND item.state='enrollment_authorized' THEN
                UPDATE public.mfa_recovery_enrollments SET consumed_at=clock_timestamp(),ciphertext=NULL WHERE request_id=p_case;
                UPDATE public.mfa_recovery_requests SET state='recovery_locked' WHERE id=p_case;
                event_type:='mfa_recovery_disputed';
            ELSIF p_action='reopen' AND item.state IN ('enrollment_authorized','recovery_locked') THEN
                IF actor=item.reviewer OR actor=item.approver OR EXISTS (
                    SELECT FROM public.mfa_recovery_enrollments WHERE request_id=p_case
                        AND expires_at>clock_timestamp() AND consumed_at IS NULL
                ) THEN RETURN 'denied'; END IF;
                UPDATE public.mfa_recovery_requests SET state='recovery_locked' WHERE id=p_case;
                INSERT INTO public.mfa_recovery_requests (
                    id,user_id,organization_id,source_id,credential_version,state
                ) SELECT p_event,account,item.organization_id,item.source_id,credential_version,'pending_identity'
                  FROM public.users WHERE id=account;
                event_type:='mfa_recovery_reopened';
            ELSIF p_action='verify' AND item.state='pending_identity' AND p_source=item.source_id THEN
                UPDATE public.mfa_recovery_requests SET state='pending_review',reviewer=actor,
                    authority_version=current_version,
                    reviewer_version=(SELECT credential_version FROM public.users WHERE id=actor),
                    reviewer_epoch=(SELECT grant_epoch FROM public.organization_memberships
                        WHERE organization_id=scope AND user_id=actor)
                WHERE id=p_case;
                event_type:='mfa_recovery_reviewed';
            ELSIF p_action='approve' AND item.state='pending_review' AND actor<>item.reviewer
                AND item.authority_version=current_version
                AND EXISTS (SELECT FROM public.users WHERE id=item.reviewer AND credential_version=item.reviewer_version)
                AND public.veriq_recovery_permission(item.reviewer,item.organization_id,'mfa.recovery.verify') THEN
                UPDATE public.mfa_recovery_requests SET state='approved_waiting',approver=actor,
                    approved_at=clock_timestamp(),
                    approver_version=(SELECT credential_version FROM public.users WHERE id=actor)
                WHERE id=p_case;
                event_type:='mfa_recovery_approved';
            ELSIF p_action='dispute' AND item.state IN ('pending_identity','pending_review','approved_waiting') THEN
                UPDATE public.mfa_recovery_requests SET state='disputed' WHERE id=p_case;
                event_type:='mfa_recovery_disputed';
            ELSIF p_action='reopen' AND item.state IN ('pending_identity','disputed','pending_review','approved_waiting')
                AND actor IS DISTINCT FROM item.reviewer AND actor IS DISTINCT FROM item.approver THEN
                UPDATE public.mfa_recovery_requests SET state='pending_identity',reviewer=NULL,approver=NULL,
                    reviewer_epoch=NULL,authority_version=NULL,approved_at=NULL,approved_event=NULL,
                    credential_version=(SELECT credential_version FROM public.users WHERE id=account)
                WHERE id=p_case;
                event_type:='mfa_recovery_reopened';
            ELSIF p_action='release' AND item.state='approved_waiting' AND actor=item.approver
                AND item.authority_version=current_version AND octet_length(p_capability)=32
                AND EXISTS (SELECT FROM public.users WHERE id=item.reviewer AND credential_version=item.reviewer_version)
                AND EXISTS (SELECT FROM public.users WHERE id=actor AND credential_version=item.approver_version)
                AND item.approved_at+interval '72 hours'>clock_timestamp()
                AND public.veriq_recovery_permission(item.reviewer,item.organization_id,'mfa.recovery.verify')
                AND (item.organization_id IS NULL OR EXISTS (SELECT FROM public.organization_memberships
                    WHERE organization_id=item.organization_id AND user_id=item.reviewer AND grant_epoch=item.reviewer_epoch))
                AND EXISTS (SELECT FROM public.notification_outbox WHERE event_id=item.approved_event
                    AND delivered_at+interval '24 hours'<=clock_timestamp())
            THEN
                PERFORM public.veriq_mfa_reset_sessions(account);
                DELETE FROM public.mfa_factors WHERE user_id=account;
                INSERT INTO public.mfa_recovery_holds (user_id,request_id) VALUES (account,p_case)
                ON CONFLICT (user_id) DO UPDATE SET request_id=excluded.request_id;
                INSERT INTO public.mfa_recovery_enrollments (request_id,digest,credential_version,expires_at)
                VALUES (p_case,p_capability,item.credential_version+1,clock_timestamp()+interval '15 minutes');
                UPDATE public.mfa_recovery_requests SET state='enrollment_authorized' WHERE id=p_case;
                event_type:='mfa_recovery_released';
            ELSE RETURN 'denied'; END IF;

            INSERT INTO public.mfa_recovery_actions VALUES (p_event,p_case,actor,p_action);
            IF NOT public.veriq_auth_append_event(
                p_event,p_event,p_correlation,event_type,'succeeded',actor,account,
                p_action IN ('approve','dispute','release')
            ) THEN RAISE EXCEPTION 'Conflicting recovery event'; END IF;
            IF p_action='approve' THEN
                UPDATE public.mfa_recovery_requests SET approved_event=p_event WHERE id=p_case;
            END IF;
            RETURN 'applied';
        END;
        $$;
    """)
    install("veriq_recovery_permission(uuid,uuid,text)")
    install("veriq_recovery_superadmin(uuid)")
    for signature in list(FUNCTIONS)[:2]:
        install(signature, FUNCTIONS[signature])


def create_enrollment() -> None:
    op.execute("""
        GRANT INSERT ON public.mfa_factors, public.mfa_recovery_codes TO veriq_session_store;

        CREATE FUNCTION public.veriq_recovery_enrollment(
            p_case uuid,p_digest bytea,p_binding bytea,p_proof uuid,p_password_digest bytea,
            p_factor uuid,p_key text,p_ciphertext bytea
        ) RETURNS TABLE (user_id uuid,factor_id uuid,key_id text,ciphertext bytea)
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
        DECLARE account uuid; enrollment public.mfa_recovery_enrollments%ROWTYPE;
        BEGIN
            SELECT r.user_id INTO account FROM public.mfa_recovery_requests r
            JOIN public.mfa_recovery_enrollments e ON e.request_id=r.id
            WHERE r.id=p_case AND e.digest=p_digest;
            IF NOT FOUND THEN RETURN; END IF;
            PERFORM pg_advisory_xact_lock(hashtextextended(account::text,7007));
            PERFORM pg_advisory_xact_lock_shared(670013::bigint);
            SELECT e.* INTO enrollment FROM public.mfa_recovery_enrollments e
            JOIN public.mfa_recovery_holds h ON h.request_id=e.request_id
            JOIN public.users u ON u.id=h.user_id
            JOIN public.mfa_recovery_requests r ON r.id=e.request_id
            JOIN public.mfa_recovery_authority a ON a.id AND a.revision=r.authority_version
            WHERE e.request_id=p_case AND e.digest=p_digest AND e.consumed_at IS NULL
                AND e.attempts<5
                AND e.expires_at>clock_timestamp() AND e.credential_version=u.credential_version
                AND u.disabled_at IS NULL AND u.email_verified_at IS NOT NULL
                AND r.state='enrollment_authorized' AND NOT public.veriq_recovery_superadmin(u.id)
                AND EXISTS (SELECT FROM public.users WHERE id=r.reviewer AND disabled_at IS NULL
                    AND credential_version=r.reviewer_version)
                AND EXISTS (SELECT FROM public.users WHERE id=r.approver AND disabled_at IS NULL
                    AND credential_version=r.approver_version)
                FOR UPDATE OF e;
            IF NOT FOUND OR octet_length(p_binding)<>32 THEN RETURN; END IF;
            IF p_proof IS NOT NULL THEN
                UPDATE public.auth_credential_proofs AS p SET consumed_at=clock_timestamp()
                WHERE p.id=p_proof AND p.proof_hash=p_password_digest AND p.user_id=account AND p.mfa_level=0
                    AND p.credential_version=enrollment.credential_version AND p.consumed_at IS NULL
                    AND p.expires_at>clock_timestamp();
                IF NOT FOUND THEN RETURN; END IF;
                UPDATE public.mfa_recovery_enrollments e SET factor_id=p_factor,key_id=p_key,
                    ciphertext=p_ciphertext,binding=p_binding WHERE request_id=p_case AND e.factor_id IS NULL;
                SELECT * INTO enrollment FROM public.mfa_recovery_enrollments WHERE request_id=p_case;
            END IF;
            IF enrollment.binding IS DISTINCT FROM p_binding OR enrollment.factor_id IS NULL THEN RETURN; END IF;
            RETURN QUERY SELECT account,enrollment.factor_id,enrollment.key_id,enrollment.ciphertext;
        END;
        $$;

        CREATE FUNCTION public.veriq_recovery_reject(
            p_case uuid,p_digest bytea,p_binding bytea,p_event uuid,p_correlation uuid
        ) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
        DECLARE prepared record;
        BEGIN
            SELECT * INTO prepared FROM public.veriq_recovery_enrollment(
                p_case,p_digest,p_binding,NULL,NULL,NULL,NULL,NULL
            );
            IF NOT FOUND THEN RETURN; END IF;
            UPDATE public.mfa_recovery_enrollments SET attempts=attempts+1,
                consumed_at=CASE WHEN attempts=4 THEN clock_timestamp() ELSE consumed_at END,
                ciphertext=CASE WHEN attempts=4 THEN NULL ELSE ciphertext END
            WHERE request_id=p_case;
            PERFORM public.veriq_auth_append_event(
                p_event,p_event,p_correlation,'mfa_recovery_attempt','denied',
                prepared.user_id,prepared.user_id,false
            );
        END;
        $$;

        CREATE FUNCTION public.veriq_recovery_complete(
            p_case uuid,p_digest bytea,p_binding bytea,p_counter bigint,p_salts bytea[],p_codes bytea[],
            p_event uuid,p_correlation uuid
        ) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
        DECLARE prepared record;
        BEGIN
            SELECT * INTO prepared FROM public.veriq_recovery_enrollment(
                p_case,p_digest,p_binding,NULL,NULL,NULL,NULL,NULL
            );
            IF NOT FOUND OR p_counter<0 OR cardinality(p_salts)<>10 OR cardinality(p_codes)<>10
            THEN RETURN false; END IF;
            INSERT INTO public.mfa_factors (user_id,id,key_id,ciphertext,confirmed_at,pending_until,last_counter)
            VALUES (prepared.user_id,prepared.factor_id,prepared.key_id,prepared.ciphertext,clock_timestamp(),
                clock_timestamp(),p_counter);
            INSERT INTO public.mfa_recovery_codes (factor_id,salt,digest)
            SELECT prepared.factor_id,salt,digest FROM unnest(p_salts,p_codes) AS codes(salt,digest);
            UPDATE public.mfa_recovery_enrollments SET consumed_at=clock_timestamp(),ciphertext=NULL
            WHERE request_id=p_case;
            DELETE FROM public.mfa_recovery_holds WHERE request_id=p_case;
            UPDATE public.mfa_recovery_requests SET state='completed' WHERE id=p_case;
            PERFORM public.veriq_mfa_reset_sessions(prepared.user_id);
            IF NOT public.veriq_auth_append_event(
                p_event,p_event,p_correlation,'mfa_recovery_completed','succeeded',
                prepared.user_id,prepared.user_id,true
            ) THEN RAISE EXCEPTION 'Conflicting recovery event'; END IF;
            RETURN true;
        END;
        $$;
    """)
    for signature in list(FUNCTIONS)[2:]:
        install(signature, FUNCTIONS[signature])


def extend_notices(enabled: bool = True) -> None:
    extra = (
        ", 'mfa_recovery_started', 'mfa_recovery_approved', 'mfa_recovery_disputed', "
        "'mfa_recovery_released', 'mfa_recovery_completed'"
        if enabled
        else ""
    )
    op.execute(f"""
        CREATE OR REPLACE FUNCTION public.veriq_password_notice_claim(p_claim uuid)
        RETURNS TABLE (event_id uuid, email text, event_type text)
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
            WITH candidate AS (
                SELECT n.event_id, u.email_normalized, e.event_type
                FROM public.notification_outbox AS n JOIN public.auth_audit_events AS e ON e.id=n.event_id
                JOIN public.users AS u ON u.id=e.target_id
                WHERE p_claim IS NOT NULL AND n.delivered_at IS NULL
                    AND (n.lease_until IS NULL OR n.lease_until <= clock_timestamp())
                    AND e.event_type IN ('password_changed','password_reset'{extra})
                    AND u.email_verified_at IS NOT NULL
                ORDER BY e.created_at,n.event_id LIMIT 1 FOR UPDATE OF n SKIP LOCKED
            )
            UPDATE public.notification_outbox AS n SET claim_id=p_claim,
                lease_until=clock_timestamp()+interval '30 seconds', attempts=n.attempts+1
            FROM candidate AS c WHERE n.event_id=c.event_id
            RETURNING n.event_id,c.email_normalized::text,c.event_type::text
        $$;
    """)


def downgrade() -> None:
    op.execute("""
        LOCK TABLE public.mfa_recovery_requests,public.mfa_recovery_sources IN ACCESS EXCLUSIVE MODE;
        DO $$
        BEGIN
            IF EXISTS (SELECT FROM public.mfa_recovery_requests) OR EXISTS (SELECT FROM public.mfa_recovery_sources)
                OR EXISTS (SELECT FROM public.mfa_challenges WHERE resource_id IS NOT NULL)
                OR EXISTS (SELECT FROM public.mfa_session_assurance WHERE resource_id IS NOT NULL)
            THEN RAISE EXCEPTION 'Downgrade requires empty MFA recovery history'; END IF;
        END;
        $$;
    """)
    extend_notices(False)
    for signature in reversed(FUNCTIONS):
        op.execute(f"DROP FUNCTION public.{signature}")
    for table in AUTHORITY_TABLES:
        op.execute(f"DROP TRIGGER mfa_recovery_authority_changed ON public.{table}")
    op.execute("""
        DROP FUNCTION public.veriq_recovery_permission(uuid,uuid,text);
        DROP FUNCTION public.veriq_recovery_superadmin(uuid);
        DROP FUNCTION public.veriq_recovery_authority_changed();
        DROP FUNCTION public.veriq_session_limits(uuid,uuid,smallint,interval[]);
        ALTER FUNCTION public.veriq_pre_recovery_session_limits(uuid,uuid,smallint,interval[])
            RENAME TO veriq_session_limits;
        DROP FUNCTION public.veriq_mfa_account(uuid,bigint);
        ALTER FUNCTION public.veriq_pre_recovery_mfa_account(uuid,bigint) RENAME TO veriq_mfa_account;
        GRANT EXECUTE ON FUNCTION public.veriq_mfa_account(uuid,bigint) TO veriq_mfa_verifier;
        DROP POLICY recovery_permission_lookup ON public.organization_role_permissions;
        REVOKE SELECT (organization_id,role_id,permission_code) ON public.organization_role_permissions FROM veriq_session_store;
        REVOKE SELECT (role_id,permission_code) ON public.platform_role_permissions FROM veriq_session_store;
        REVOKE DELETE, INSERT ON public.mfa_factors FROM veriq_session_store;
        REVOKE INSERT ON public.mfa_recovery_codes FROM veriq_session_store;
        DROP TABLE public.mfa_recovery_enrollments,public.mfa_recovery_actions,public.mfa_recovery_holds,
            public.mfa_recovery_requests,public.mfa_recovery_sources,public.mfa_recovery_authority;
        DELETE FROM public.platform_role_permissions WHERE role_id IN (
            SELECT id FROM public.platform_roles WHERE code IN ('mfa_recovery_approver','mfa_recovery_verifier')
        );
        DELETE FROM public.platform_roles WHERE code IN ('mfa_recovery_approver','mfa_recovery_verifier');
        ALTER TABLE public.platform_roles DROP CONSTRAINT ck_platform_roles_code;
        ALTER TABLE public.platform_roles ADD CONSTRAINT ck_platform_roles_code CHECK (code='superadmin');
        ALTER TABLE public.mfa_challenges DROP CONSTRAINT mfa_challenges_purpose_check, DROP COLUMN resource_id;
        ALTER TABLE public.mfa_challenges ADD CONSTRAINT mfa_challenges_purpose_check
            CHECK (purpose IN ('login','enroll','sensitive','factor_disable','password_change'));
        ALTER TABLE public.mfa_session_assurance DROP CONSTRAINT mfa_session_assurance_purpose_check, DROP COLUMN resource_id;
        ALTER TABLE public.mfa_session_assurance ADD CONSTRAINT mfa_session_assurance_purpose_check
            CHECK (purpose IN ('sensitive','factor_disable','password_change'));
        ALTER TABLE public.auth_audit_events DROP CONSTRAINT ck_auth_event_type;
        ALTER TABLE public.auth_audit_events ADD CONSTRAINT ck_auth_event_type CHECK (
            event_type IN ('registration_attempt','login_attempt','mfa_attempt','password_reset_attempt',
                'mfa_recovery_attempt','session_issued','session_revoked','sessions_revoked','password_verified',
                'login_mfa_required','session_rotated','password_changed','password_reset')
        );
        ALTER TABLE public.auth_audit_events DROP CONSTRAINT ck_auth_event_notify;
        ALTER TABLE public.auth_audit_events ADD CONSTRAINT ck_auth_event_notify CHECK (
            NOT notify OR (target_id IS NOT NULL AND result='succeeded' AND event_type IN (
                'sessions_revoked','password_changed','password_reset'))
        );
    """)
