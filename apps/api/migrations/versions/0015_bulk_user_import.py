"""Tenant-scoped, expiring organization import batches."""

from alembic import op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None

TABLES = ("user_import_batches", "user_import_rows", "user_import_events")
SIGNATURE = "uuid,bytea,interval[],uuid,text,uuid,bytea,jsonb"


def upgrade() -> None:
    op.execute("""
        CREATE TABLE public.user_import_batches (
            organization_id uuid NOT NULL,
            id uuid NOT NULL,
            actor_id uuid NOT NULL,
            fingerprint bytea NOT NULL CHECK (octet_length(fingerprint)=32),
            created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '24 hours',
            confirmed_at timestamptz,
            PRIMARY KEY (organization_id,id),
            UNIQUE (organization_id,actor_id,fingerprint),
            FOREIGN KEY (organization_id,actor_id) REFERENCES public.organization_memberships(organization_id,user_id)
        );
        CREATE INDEX user_import_batch_expiry ON public.user_import_batches(expires_at);
        CREATE TABLE public.user_import_rows (
            organization_id uuid NOT NULL,
            batch_id uuid NOT NULL,
            row_number integer NOT NULL CHECK (row_number BETWEEN 1 AND 262145),
            request_id uuid,
            email text CHECK (length(email)<=254 AND lower(email)=email),
            state text NOT NULL CHECK (state IN ('invalid_email','unexpected_columns','duplicate_in_file',
                'new_email','existing_account','existing_membership','inactive_membership',
                'account_unavailable','awaiting_verification','created','claimed')),
            PRIMARY KEY (organization_id,batch_id,row_number),
            FOREIGN KEY (organization_id,batch_id) REFERENCES public.user_import_batches(organization_id,id) ON DELETE CASCADE,
            FOREIGN KEY (organization_id,request_id) REFERENCES public.join_requests(organization_id,id)
        );
        CREATE INDEX user_import_claim_email ON public.user_import_rows(organization_id,email)
            WHERE state='awaiting_verification';
        CREATE TABLE public.user_import_events (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id uuid NOT NULL REFERENCES public.organizations(id),
            batch_id uuid NOT NULL,
            actor_id uuid NOT NULL REFERENCES public.users(id),
            action text NOT NULL CHECK (action IN ('preview','confirm','claim')),
            created_at timestamptz NOT NULL DEFAULT clock_timestamp()
        );
        INSERT INTO public.permissions (scope,code) VALUES ('organization','organization.import.manage');
        INSERT INTO public.organization_role_permissions (organization_id,role_id,permission_code)
            SELECT organization_id,id,'organization.import.manage' FROM public.organization_roles WHERE code='org_admin';
    """)
    for table in TABLES:
        op.execute(f"""
            ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY;
            ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY;
            CREATE POLICY import_tenant ON public.{table} TO veriq_session_store
                USING (organization_id::text=current_setting('veriq.join_org',true))
                WITH CHECK (organization_id::text=current_setting('veriq.join_org',true));
        """)
    op.execute("""
        CREATE POLICY import_cleanup ON public.user_import_batches TO veriq_session_store
            USING (current_setting('veriq.import_cleanup',true)='on' AND expires_at<=statement_timestamp());
        GRANT SELECT, INSERT, UPDATE, DELETE ON public.user_import_batches TO veriq_session_store;
        GRANT SELECT, INSERT, UPDATE ON public.user_import_rows TO veriq_session_store;
        GRANT INSERT ON public.user_import_events TO veriq_session_store;

        CREATE FUNCTION public.veriq_import_purge() RETURNS integer
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp SET veriq.join_org='' SET veriq.import_cleanup='on' AS $$
        DECLARE deleted integer;
        BEGIN
            WITH expired AS (
                SELECT organization_id,id FROM public.user_import_batches
                WHERE expires_at<=statement_timestamp() ORDER BY expires_at LIMIT 25 FOR UPDATE SKIP LOCKED
            )
            DELETE FROM public.user_import_batches b USING expired e
                WHERE b.organization_id=e.organization_id AND b.id=e.id;
            GET DIAGNOSTICS deleted=ROW_COUNT;
            RETURN deleted;
        END;
        $$;
        ALTER FUNCTION public.veriq_import_purge() OWNER TO veriq_session_store;
        REVOKE ALL ON FUNCTION public.veriq_import_purge() FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION public.veriq_import_purge() TO veriq_worker;
    """)
    create_commands()


def create_commands() -> None:
    op.execute("""
        CREATE FUNCTION public.veriq_user_import(
            p_session uuid,p_secret bytea,p_limits interval[],p_org uuid,p_action text,
            p_batch uuid,p_fingerprint bytea,p_rows jsonb
        ) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp SET veriq.join_org='' SET veriq.import_cleanup='off' AS $$
        DECLARE actor uuid; actor_org uuid; actor_email text; item record; batch public.user_import_batches%ROWTYPE;
            user_id_found uuid; member_id uuid; member_status text; verified boolean; state_now text;
        BEGIN
            IF p_action IS NULL OR p_action NOT IN ('authorize','preview','confirm','result','claim') THEN RETURN NULL; END IF;
            SELECT s.user_id,s.organization_id,u.email_normalized::text INTO actor,actor_org,actor_email
                FROM public.auth_sessions s JOIN public.users u ON u.id=s.user_id
                WHERE s.id=p_session AND s.token_hash=p_secret AND u.email_verified_at IS NOT NULL AND u.disabled_at IS NULL;
            IF actor IS NULL OR (p_action<>'claim' AND actor_org IS DISTINCT FROM p_org) THEN RETURN NULL; END IF;
            PERFORM set_config('veriq.join_org',p_org::text,true);
            PERFORM pg_advisory_xact_lock(hashtextextended(actor::text,7007));
            PERFORM pg_advisory_xact_lock(670013::bigint);
            IF NOT public.veriq_session_current(p_session,p_secret,actor,actor_org,p_limits)
                OR NOT EXISTS (SELECT FROM public.organizations WHERE id=p_org AND status='active')
            THEN RETURN NULL; END IF;
            IF p_action<>'claim' AND (
                NOT public.veriq_recovery_permission(actor,p_org,'organization.import.manage')
                OR NOT public.veriq_mfa_fresh(p_session,p_secret,p_limits,'sensitive',interval '5 minutes')
            ) THEN RETURN NULL; END IF;

            IF p_action='authorize' THEN RETURN jsonb_build_object('status','authorized'); END IF;
            IF p_action='claim' THEN
                SELECT r.batch_id,r.row_number INTO item FROM public.user_import_rows r JOIN public.user_import_batches b
                    ON r.organization_id=b.organization_id AND r.batch_id=b.id
                    WHERE r.organization_id=p_org AND r.batch_id=p_batch AND r.email=actor_email
                        AND r.state='awaiting_verification' AND b.confirmed_at IS NOT NULL
                        AND b.expires_at>clock_timestamp() FOR UPDATE OF b;
                IF NOT FOUND OR EXISTS (SELECT FROM public.organization_memberships
                    WHERE organization_id=p_org AND user_id=actor) THEN RETURN NULL; END IF;
                member_id:=gen_random_uuid();
                INSERT INTO public.organization_memberships(id,organization_id,user_id,status)
                    VALUES (member_id,p_org,actor,'pending');
                INSERT INTO public.join_requests(id,organization_id,user_id,membership_id)
                    VALUES (member_id,p_org,actor,member_id);
                UPDATE public.user_import_rows SET state='claimed',email=NULL,request_id=member_id
                    WHERE organization_id=p_org AND batch_id=p_batch AND row_number=item.row_number;
                INSERT INTO public.user_import_events(organization_id,batch_id,actor_id,action)
                    VALUES (p_org,p_batch,actor,'claim');
                RETURN jsonb_build_object('status','pending','request_id',member_id);
            END IF;

            IF p_action='preview' THEN
                IF jsonb_typeof(p_rows) IS DISTINCT FROM 'array' OR jsonb_array_length(p_rows) NOT BETWEEN 1 AND 500
                    OR octet_length(p_fingerprint) IS DISTINCT FROM 32 THEN RETURN NULL; END IF;
                SELECT * INTO batch FROM public.user_import_batches
                    WHERE organization_id=p_org AND actor_id=actor AND fingerprint=p_fingerprint FOR UPDATE;
                IF FOUND AND batch.expires_at<=clock_timestamp() THEN
                    DELETE FROM public.user_import_batches WHERE organization_id=p_org AND id=batch.id;
                    batch.id:=NULL;
                END IF;
                IF batch.id IS NULL THEN
                    INSERT INTO public.user_import_batches(organization_id,id,actor_id,fingerprint)
                        VALUES (p_org,p_batch,actor,p_fingerprint) RETURNING * INTO batch;
                    INSERT INTO public.user_import_rows(organization_id,batch_id,row_number,email,state)
                        SELECT p_org,batch.id,r.number,r.email,
                            CASE WHEN r.error IN ('invalid_email','unexpected_columns','duplicate_in_file') THEN r.error
                                WHEN u.id IS NULL THEN 'new_email'
                                WHEN u.disabled_at IS NOT NULL OR u.email_verified_at IS NULL THEN 'account_unavailable'
                                WHEN m.status IN ('suspended','revoked') THEN 'inactive_membership'
                                WHEN m.id IS NOT NULL THEN 'existing_membership'
                                ELSE 'existing_account' END
                        FROM jsonb_to_recordset(p_rows) AS r(number integer,email text,error text)
                        LEFT JOIN public.users u ON u.email_normalized::text=r.email
                        LEFT JOIN public.organization_memberships m ON m.organization_id=p_org AND m.user_id=u.id;
                    INSERT INTO public.user_import_events(organization_id,batch_id,actor_id,action)
                        VALUES (p_org,batch.id,actor,'preview');
                END IF;
            ELSE
                SELECT * INTO batch FROM public.user_import_batches
                    WHERE organization_id=p_org AND id=p_batch AND actor_id=actor
                        AND expires_at>clock_timestamp() FOR UPDATE;
                IF NOT FOUND THEN RETURN NULL; END IF;
                IF p_action='confirm' AND batch.fingerprint IS DISTINCT FROM p_fingerprint THEN RETURN NULL; END IF;
            END IF;

            IF p_action='confirm' AND batch.confirmed_at IS NULL THEN
                FOR item IN SELECT row_number,email FROM public.user_import_rows
                    WHERE organization_id=p_org AND batch_id=batch.id AND state IN (
                        'new_email','existing_account','existing_membership','inactive_membership','account_unavailable'
                    ) ORDER BY row_number LOOP
                    member_id:=NULL;
                    SELECT u.id, u.disabled_at IS NULL AND u.email_verified_at IS NOT NULL,m.status
                        INTO user_id_found,verified,member_status
                        FROM public.users u LEFT JOIN public.organization_memberships m
                            ON m.organization_id=p_org AND m.user_id=u.id
                        WHERE u.email_normalized::text=item.email;
                    IF user_id_found IS NULL OR NOT verified THEN
                        state_now:=CASE WHEN user_id_found IS NULL OR EXISTS (
                            SELECT FROM public.users WHERE id=user_id_found AND disabled_at IS NULL
                        ) THEN 'awaiting_verification' ELSE 'account_unavailable' END;
                    ELSIF member_status IS NOT NULL THEN
                        state_now:=CASE WHEN member_status IN ('suspended','revoked') THEN 'inactive_membership'
                            ELSE 'existing_membership' END;
                    ELSE
                        member_id:=gen_random_uuid();
                        INSERT INTO public.organization_memberships(id,organization_id,user_id,status)
                            VALUES (member_id,p_org,user_id_found,'pending');
                        INSERT INTO public.join_requests(id,organization_id,user_id,membership_id)
                            VALUES (member_id,p_org,user_id_found,member_id);
                        state_now:='created';
                    END IF;
                    UPDATE public.user_import_rows SET state=state_now,request_id=member_id,
                        email=CASE WHEN state_now='awaiting_verification' THEN item.email END
                        WHERE organization_id=p_org AND batch_id=batch.id AND row_number=item.row_number;
                END LOOP;
                UPDATE public.user_import_batches SET confirmed_at=clock_timestamp()
                    WHERE organization_id=p_org AND id=batch.id RETURNING * INTO batch;
                INSERT INTO public.user_import_events(organization_id,batch_id,actor_id,action)
                    VALUES (p_org,batch.id,actor,'confirm');
            END IF;
            RETURN jsonb_build_object(
                'batch_id',batch.id,'version',encode(batch.fingerprint,'hex'),'confirmed',batch.confirmed_at IS NOT NULL,
                'expires_at',batch.expires_at,'counts',(
                    SELECT jsonb_object_agg(state,total) FROM (
                        SELECT state,count(*) AS total FROM public.user_import_rows
                        WHERE organization_id=p_org AND batch_id=batch.id GROUP BY state
                    ) AS totals
                ),'rows',(
                    SELECT jsonb_agg(jsonb_build_object('row',row_number,'state',state,
                        'email',CASE WHEN batch.confirmed_at IS NULL THEN email END,
                        'request_id',request_id) ORDER BY row_number)
                    FROM public.user_import_rows WHERE organization_id=p_org AND batch_id=batch.id
                )
            );
        END;
        $$;
    """)
    op.execute(f"""
        ALTER FUNCTION public.veriq_user_import({SIGNATURE}) OWNER TO veriq_session_store;
        REVOKE ALL ON FUNCTION public.veriq_user_import({SIGNATURE}) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION public.veriq_user_import({SIGNATURE}) TO veriq_api;
    """)


def downgrade() -> None:
    op.execute(f"""
        LOCK TABLE public.user_import_events, public.user_import_rows, public.user_import_batches IN ACCESS EXCLUSIVE MODE;
        DO $$ BEGIN
            IF EXISTS (SELECT FROM public.user_import_events) THEN
                RAISE EXCEPTION 'Downgrade requires an unused import schema';
            END IF;
        END $$;
        DROP FUNCTION public.veriq_user_import({SIGNATURE});
        DROP FUNCTION public.veriq_import_purge();
        DROP TABLE public.user_import_events, public.user_import_rows, public.user_import_batches;
        DELETE FROM public.organization_role_permissions WHERE permission_code='organization.import.manage';
        DELETE FROM public.permissions WHERE scope='organization' AND code='organization.import.manage';
    """)
