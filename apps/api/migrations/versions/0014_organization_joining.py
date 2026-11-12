"""Create the protected storage for organization onboarding."""

from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE public.organization_memberships
            ADD CONSTRAINT uq_membership_join_subject UNIQUE (organization_id, id, user_id);

        CREATE TABLE public.invites (
            organization_id uuid NOT NULL REFERENCES public.organizations(id),
            id uuid NOT NULL,
            recipient_id uuid NOT NULL REFERENCES public.users(id),
            created_by uuid NOT NULL REFERENCES public.users(id),
            token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
            activates_membership boolean NOT NULL,
            created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            expires_at timestamptz NOT NULL,
            redeemed_at timestamptz,
            revoked_at timestamptz,
            PRIMARY KEY (organization_id, id),
            CHECK (expires_at > created_at),
            CHECK (expires_at <= created_at + interval '72 hours'),
            CHECK (redeemed_at IS NULL OR redeemed_at BETWEEN created_at AND expires_at),
            CHECK (revoked_at IS NULL OR revoked_at >= created_at),
            CHECK (redeemed_at IS NULL OR revoked_at IS NULL)
        );

        CREATE TABLE public.group_join_codes (
            organization_id uuid NOT NULL REFERENCES public.organizations(id),
            id uuid NOT NULL,
            created_by uuid NOT NULL REFERENCES public.users(id),
            code_hash bytea NOT NULL UNIQUE CHECK (octet_length(code_hash) = 32),
            max_uses integer NOT NULL CHECK (max_uses BETWEEN 1 AND 1000),
            uses integer NOT NULL DEFAULT 0 CHECK (uses BETWEEN 0 AND max_uses),
            created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            expires_at timestamptz NOT NULL,
            revoked_at timestamptz,
            PRIMARY KEY (organization_id, id),
            CHECK (expires_at > created_at),
            CHECK (expires_at <= created_at + interval '24 hours'),
            CHECK (revoked_at IS NULL OR revoked_at >= created_at)
        );

        CREATE TABLE public.join_requests (
            organization_id uuid NOT NULL,
            id uuid NOT NULL,
            membership_id uuid NOT NULL,
            user_id uuid NOT NULL,
            invite_id uuid,
            code_id uuid,
            state text NOT NULL DEFAULT 'pending',
            created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            reviewed_at timestamptz,
            reviewed_by uuid REFERENCES public.users(id),
            PRIMARY KEY (organization_id, id),
            FOREIGN KEY (organization_id, membership_id, user_id)
                REFERENCES public.organization_memberships(organization_id, id, user_id),
            FOREIGN KEY (organization_id, invite_id) REFERENCES public.invites(organization_id, id),
            FOREIGN KEY (organization_id, code_id) REFERENCES public.group_join_codes(organization_id, id),
            CHECK (num_nonnulls(invite_id, code_id) <= 1),
            CHECK (
                (state = 'pending' AND reviewed_at IS NULL AND reviewed_by IS NULL)
                OR (state IN ('approved', 'rejected') AND reviewed_at IS NOT NULL
                    AND reviewed_at >= created_at AND reviewed_by IS NOT NULL AND reviewed_by <> user_id)
            )
        );

        CREATE UNIQUE INDEX uq_join_requests_pending
            ON public.join_requests(organization_id, membership_id) WHERE state = 'pending';

        ALTER TABLE public.invites ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.invites FORCE ROW LEVEL SECURITY;
        ALTER TABLE public.group_join_codes ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.group_join_codes FORCE ROW LEVEL SECURITY;
        ALTER TABLE public.join_requests ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.join_requests FORCE ROW LEVEL SECURITY;
    """)
    create_operations()


def downgrade() -> None:
    op.execute("""
        LOCK TABLE public.join_requests, public.invites, public.group_join_codes,
            public.join_audit_events, public.organization_join_intake IN ACCESS EXCLUSIVE MODE;
        DO $$
        BEGIN
            IF EXISTS (SELECT FROM public.join_requests) OR EXISTS (SELECT FROM public.invites)
                OR EXISTS (SELECT FROM public.group_join_codes) OR EXISTS (SELECT FROM public.join_audit_events)
                OR EXISTS (SELECT FROM public.organization_join_intake)
            THEN RAISE EXCEPTION 'Downgrade requires empty onboarding tables'; END IF;
        END;
        $$;
        DROP FUNCTION public.veriq_organization_join(uuid,bytea,interval[],uuid,text,uuid,uuid,bytea,boolean,integer,uuid,uuid);
        DROP POLICY joining_organization ON public.organizations;
        REVOKE SELECT (id, status) ON public.organizations FROM veriq_session_store;
        DROP POLICY joining_insert ON public.organization_memberships;
        DROP POLICY joining_update ON public.organization_memberships;
        REVOKE INSERT (id, organization_id, user_id, status, joined_at),
            UPDATE (status, joined_at, updated_at, version), SELECT (status, joined_at, version)
            ON public.organization_memberships FROM veriq_session_store;
        DROP TABLE public.join_audit_events, public.organization_join_intake;
        DELETE FROM public.organization_role_permissions WHERE permission_code='organization.join.manage';
        DELETE FROM public.permissions WHERE scope='organization' AND code='organization.join.manage';
        DROP TABLE public.join_requests;
        DROP TABLE public.group_join_codes;
        DROP TABLE public.invites;
        ALTER TABLE public.organization_memberships DROP CONSTRAINT uq_membership_join_subject;
    """)


def create_operations() -> None:
    op.execute("""
        CREATE TABLE public.organization_join_intake (
            organization_id uuid PRIMARY KEY REFERENCES public.organizations(id),
            enabled boolean NOT NULL
        );

        CREATE TABLE public.join_audit_events (
            id uuid PRIMARY KEY,
            organization_id uuid NOT NULL REFERENCES public.organizations(id),
            actor_id uuid NOT NULL REFERENCES public.users(id),
            object_id uuid NOT NULL,
            action text NOT NULL CHECK (action IN (
                'issue_invite','issue_code','revoke_invite','revoke_code','redeem_invite',
                'redeem_code','apply','approve','reject','set_intake'
            )),
            correlation_id uuid NOT NULL,
            created_at timestamptz NOT NULL DEFAULT clock_timestamp()
        );

        GRANT SELECT (status, joined_at, version),
            INSERT (id, organization_id, user_id, status, joined_at),
            UPDATE (status, joined_at, updated_at, version)
            ON public.organization_memberships TO veriq_session_store;

        GRANT SELECT (id, status) ON public.organizations TO veriq_session_store;
        CREATE POLICY joining_organization ON public.organizations FOR SELECT TO veriq_session_store
            USING (id::text = current_setting('veriq.join_org', true));

        CREATE POLICY joining_insert ON public.organization_memberships FOR INSERT TO veriq_session_store
            WITH CHECK (organization_id::text = current_setting('veriq.join_org', true));
        CREATE POLICY joining_update ON public.organization_memberships FOR UPDATE TO veriq_session_store
            USING (organization_id::text = current_setting('veriq.join_org', true))
            WITH CHECK (organization_id::text = current_setting('veriq.join_org', true));

        INSERT INTO public.permissions (scope,code) VALUES ('organization','organization.join.manage');
        INSERT INTO public.organization_role_permissions (organization_id,role_id,permission_code)
            SELECT organization_id,id,'organization.join.manage' FROM public.organization_roles WHERE code='org_admin';
    """)
    for table in (
        "invites",
        "group_join_codes",
        "join_requests",
        "organization_join_intake",
        "join_audit_events",
    ):
        op.execute(f"""
            ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY;
            ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY;
            CREATE POLICY joining_scope ON public.{table} TO veriq_session_store
                USING (organization_id::text = current_setting('veriq.join_org', true))
                WITH CHECK (organization_id::text = current_setting('veriq.join_org', true));
        """)
    op.execute("""
        GRANT SELECT, INSERT, UPDATE ON public.invites, public.group_join_codes, public.join_requests,
            public.organization_join_intake TO veriq_session_store;
        GRANT INSERT ON public.join_audit_events TO veriq_session_store;

        CREATE FUNCTION public.veriq_organization_join(
            p_session uuid,p_digest bytea,p_limits interval[],p_org uuid,p_action text,
            p_object uuid,p_recipient uuid,p_secret bytea,p_flag boolean,p_quota integer,
            p_event uuid,p_correlation uuid
        ) RETURNS text
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp SET veriq.join_org = '' AS $$
        DECLARE actor uuid; actor_org uuid; subject uuid; member uuid; member_status text;
            invite public.invites%ROWTYPE; code public.group_join_codes%ROWTYPE;
            application public.join_requests%ROWTYPE; result text; active_now boolean := false;
            staff boolean; lock_key bigint; now_at timestamptz;
        BEGIN
            IF p_action IS NULL OR p_action NOT IN (
                'issue_invite','issue_code','revoke_invite','revoke_code','redeem_invite',
                'redeem_code','apply','approve','reject','set_intake','status'
            ) THEN RETURN NULL; END IF;
            SELECT user_id,organization_id INTO actor,actor_org FROM public.auth_sessions
                WHERE id=p_session AND token_hash=p_digest;
            IF actor IS NULL THEN RETURN NULL; END IF;
            staff := p_action IN ('issue_invite','issue_code','revoke_invite','revoke_code','approve','reject','set_intake');
            IF staff AND actor_org IS DISTINCT FROM p_org THEN RETURN NULL; END IF;
            PERFORM set_config('veriq.join_org',p_org::text,true);

            subject := actor;
            IF p_action IN ('approve','reject') THEN
                SELECT user_id INTO subject FROM public.join_requests WHERE organization_id=p_org AND id=p_object;
                IF subject IS NULL OR subject=actor THEN RETURN NULL; END IF;
            END IF;

            FOR lock_key IN SELECT DISTINCT k FROM unnest(ARRAY[
                hashtextextended(actor::text,7007),hashtextextended(subject::text,7007)
            ]) AS keys(k) ORDER BY k LOOP
                PERFORM pg_advisory_xact_lock(lock_key);
            END LOOP;
            -- Membership writes fire the authority trigger, so acquire its lock exclusively up front.
            PERFORM pg_advisory_xact_lock(670013::bigint);
            IF NOT public.veriq_session_current(p_session,p_digest,actor,actor_org,p_limits)
                OR NOT EXISTS (SELECT FROM public.users WHERE id=actor AND email_verified_at IS NOT NULL AND disabled_at IS NULL)
                OR NOT EXISTS (SELECT FROM public.organizations WHERE id=p_org AND status='active')
            THEN RETURN NULL; END IF;
            IF staff AND (
                NOT public.veriq_recovery_permission(actor,p_org,'organization.join.manage')
                OR NOT public.veriq_mfa_fresh(p_session,p_digest,p_limits,'sensitive',interval '5 minutes')
            ) THEN RETURN NULL; END IF;

            now_at := clock_timestamp();
            IF p_action='issue_invite' THEN
                IF NOT EXISTS (SELECT FROM public.users WHERE id=p_recipient AND email_verified_at IS NOT NULL AND disabled_at IS NULL)
                THEN RETURN NULL; END IF;
                INSERT INTO public.invites (
                    organization_id,id,recipient_id,created_by,token_hash,activates_membership,created_at,expires_at
                ) VALUES (p_org,p_object,p_recipient,actor,p_secret,p_flag,now_at,now_at+interval '72 hours');
                result := 'issued';
            ELSIF p_action='issue_code' THEN
                INSERT INTO public.group_join_codes (
                    organization_id,id,created_by,code_hash,max_uses,created_at,expires_at
                ) VALUES (p_org,p_object,actor,p_secret,p_quota,now_at,now_at+interval '24 hours');
                result := 'issued';
            ELSIF p_action='revoke_invite' THEN
                UPDATE public.invites SET revoked_at=now_at
                    WHERE organization_id=p_org AND id=p_object AND redeemed_at IS NULL AND revoked_at IS NULL;
                IF NOT FOUND THEN RETURN NULL; END IF;
                result := 'revoked';
            ELSIF p_action='revoke_code' THEN
                UPDATE public.group_join_codes SET revoked_at=now_at
                    WHERE organization_id=p_org AND id=p_object AND revoked_at IS NULL;
                IF NOT FOUND THEN RETURN NULL; END IF;
                result := 'revoked';
            ELSIF p_action='set_intake' THEN
                INSERT INTO public.organization_join_intake VALUES (p_org,p_flag)
                    ON CONFLICT (organization_id) DO UPDATE SET enabled=excluded.enabled;
                p_object := p_org;
                result := CASE WHEN p_flag THEN 'enabled' ELSE 'disabled' END;
            ELSE
                SELECT id,status INTO member,member_status FROM public.organization_memberships
                    WHERE organization_id=p_org AND user_id=subject;
                IF p_action='status' THEN RETURN member_status; END IF;
                IF member_status IN ('revoked','suspended') THEN RETURN NULL; END IF;

                IF p_action IN ('approve','reject') THEN
                    SELECT * INTO application FROM public.join_requests
                        WHERE organization_id=p_org AND id=p_object AND user_id=subject AND membership_id=member;
                    IF NOT FOUND OR application.state<>'pending' OR member_status<>'pending'
                        OR NOT EXISTS (SELECT FROM public.users WHERE id=subject AND disabled_at IS NULL AND email_verified_at IS NOT NULL)
                    THEN RETURN NULL; END IF;
                    IF p_action='approve' AND EXISTS (
                        SELECT FROM public.membership_roles r JOIN public.organization_memberships m
                          ON m.organization_id=r.organization_id AND m.id=r.membership_id AND m.grant_epoch=r.grant_epoch
                        WHERE m.organization_id=p_org AND m.id=member
                    ) THEN RETURN NULL; END IF;
                    result := CASE WHEN p_action='approve' THEN 'active' ELSE 'revoked' END;
                    UPDATE public.organization_memberships SET status=result,
                        joined_at=CASE WHEN result='active' THEN coalesce(joined_at,now_at) ELSE joined_at END,
                        updated_at=now_at,version=version+1
                        WHERE organization_id=p_org AND id=member AND status='pending';
                    IF NOT FOUND THEN RETURN NULL; END IF;
                    UPDATE public.join_requests SET state=CASE WHEN p_action='approve' THEN 'approved' ELSE 'rejected' END,
                        reviewed_at=now_at,reviewed_by=actor WHERE organization_id=p_org AND id=p_object;
                ELSE
                    IF p_action='redeem_invite' THEN
                        SELECT * INTO invite FROM public.invites WHERE organization_id=p_org AND id=p_object
                            AND recipient_id=actor AND token_hash=p_secret AND expires_at>now_at
                            AND revoked_at IS NULL AND redeemed_at IS NULL FOR UPDATE;
                        IF NOT FOUND THEN RETURN NULL; END IF;
                        active_now := invite.activates_membership;
                    ELSIF p_action='redeem_code' THEN
                        SELECT * INTO code FROM public.group_join_codes WHERE organization_id=p_org AND id=p_object
                            AND code_hash=p_secret AND expires_at>now_at AND revoked_at IS NULL AND uses<max_uses FOR UPDATE;
                        IF NOT FOUND THEN RETURN NULL; END IF;
                    ELSIF NOT EXISTS (
                        SELECT FROM public.organization_join_intake WHERE organization_id=p_org AND enabled
                    ) THEN RETURN NULL;
                    END IF;
                    IF member_status='active' THEN RETURN 'active'; END IF;
                    SELECT * INTO application FROM public.join_requests
                        WHERE organization_id=p_org AND membership_id=member AND state='pending';
                    IF FOUND THEN RETURN 'pending:' || application.id::text; END IF;
                    -- An invitation only activates a new membership. Existing pending memberships require review.
                    active_now := active_now AND member IS NULL;
                    result := CASE WHEN active_now THEN 'active' ELSE 'pending' END;
                    IF member IS NULL THEN
                        INSERT INTO public.organization_memberships (id,organization_id,user_id,status,joined_at)
                            VALUES (p_event,p_org,actor,result,CASE WHEN active_now THEN now_at END);
                        member := p_event;
                    END IF;
                    IF NOT active_now THEN
                        INSERT INTO public.join_requests (organization_id,id,membership_id,user_id,invite_id,code_id)
                            VALUES (p_org,p_event,member,actor,invite.id,code.id);
                    END IF;
                    IF invite.id IS NOT NULL THEN
                        UPDATE public.invites SET redeemed_at=now_at WHERE organization_id=p_org AND id=invite.id;
                    ELSIF code.id IS NOT NULL THEN
                        UPDATE public.group_join_codes SET uses=uses+1 WHERE organization_id=p_org AND id=code.id;
                    END IF;
                    p_object := coalesce(p_object,member);
                END IF;
            END IF;
            INSERT INTO public.join_audit_events (id,organization_id,actor_id,object_id,action,correlation_id)
                VALUES (p_event,p_org,actor,p_object,p_action,p_correlation);
            IF result='pending' THEN RETURN result || ':' || p_event::text; END IF;
            RETURN result;
        END;
        $$;
        ALTER FUNCTION public.veriq_organization_join(uuid,bytea,interval[],uuid,text,uuid,uuid,bytea,boolean,integer,uuid,uuid)
            OWNER TO veriq_session_store;
        REVOKE ALL ON FUNCTION public.veriq_organization_join(uuid,bytea,interval[],uuid,text,uuid,uuid,bytea,boolean,integer,uuid,uuid)
            FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION public.veriq_organization_join(uuid,bytea,interval[],uuid,text,uuid,uuid,bytea,boolean,integer,uuid,uuid)
            TO veriq_api;
    """)
