"""Persist worker leases and fence completion by owner and attempt."""

from alembic import op

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        DROP FUNCTION public.veriq_queue_claim();
        DROP FUNCTION public.veriq_queue_finish(uuid,boolean);
        ALTER TABLE public.background_jobs
            DROP COLUMN claim_xid,
            ADD COLUMN lease_owner uuid,
            ADD COLUMN lease_until timestamptz,
            DROP CONSTRAINT background_jobs_status_check,
            ADD CHECK (status IN ('pending','running','succeeded','failed')),
            ADD CHECK (
                (status='running' AND lease_owner IS NOT NULL AND lease_until IS NOT NULL AND attempts>0)
                OR (status<>'running' AND lease_owner IS NULL AND lease_until IS NULL)
            );
        CREATE INDEX ix_background_jobs_running_lease
            ON public.background_jobs(lease_until,id) WHERE status='running';
        GRANT UPDATE (lease_owner,lease_until) ON public.background_jobs TO veriq_queue_store;

        CREATE FUNCTION public.veriq_queue_claim(p_owner uuid)
        RETURNS TABLE(id uuid,kind text,attempts integer)
        LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
        BEGIN
            IF p_owner IS NULL THEN
                RAISE EXCEPTION 'Queue owner is required' USING ERRCODE='22004';
            END IF;
            WITH exhausted AS (
                SELECT j.id FROM public.background_jobs j
                WHERE j.attempts=3 AND (
                    (j.status='running' AND j.lease_until<=clock_timestamp())
                    OR j.status='pending'
                )
                ORDER BY j.id LIMIT 32 FOR UPDATE SKIP LOCKED
            )
            UPDATE public.background_jobs j
            SET status='failed',lease_owner=NULL,lease_until=NULL
            FROM exhausted e WHERE j.id=e.id;

            RETURN QUERY
            WITH candidate AS (
                SELECT j.id FROM public.background_jobs j
                WHERE j.attempts<3 AND (
                    (j.status='pending' AND j.available_at<=clock_timestamp())
                    OR (j.status='running' AND
                        j.lease_until + make_interval(secs=>power(2,j.attempts))<=clock_timestamp())
                )
                ORDER BY CASE WHEN j.status='running' THEN j.lease_until ELSE j.available_at END,j.id
                LIMIT 1 FOR UPDATE SKIP LOCKED
            )
            UPDATE public.background_jobs j SET status='running',attempts=j.attempts+1,
                lease_owner=p_owner,lease_until=clock_timestamp()+interval '12 seconds'
            FROM candidate c WHERE j.id=c.id
            RETURNING j.id,j.kind::text,j.attempts;
        END $$;

        CREATE FUNCTION public.veriq_queue_heartbeat(p_id uuid,p_owner uuid,p_token integer)
        RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
            WITH renewed AS (
                UPDATE public.background_jobs j SET lease_until=clock_timestamp()+interval '12 seconds'
                WHERE j.id=p_id AND j.status='running' AND j.lease_owner=p_owner
                  AND j.attempts=p_token AND j.lease_until>clock_timestamp()
                RETURNING 1
            )
            SELECT EXISTS (SELECT FROM renewed)
        $$;

        CREATE FUNCTION public.veriq_queue_finish(
            p_id uuid,p_owner uuid,p_token integer,p_success boolean
        ) RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
            WITH finished AS (
                UPDATE public.background_jobs j SET
                    status=CASE WHEN j.kind='probe' AND p_success THEN 'succeeded'
                                WHEN j.kind='probe' AND j.attempts<3 THEN 'pending'
                                ELSE 'failed' END,
                    available_at=clock_timestamp()+make_interval(secs=>
                        CASE WHEN j.kind='probe' AND NOT p_success AND j.attempts<3
                             THEN power(2,j.attempts) ELSE 0 END),
                    lease_owner=NULL,lease_until=NULL
                WHERE j.id=p_id AND j.status='running' AND j.lease_owner=p_owner
                  AND j.attempts=p_token AND j.lease_until>clock_timestamp()
                  AND p_success IS NOT NULL
                RETURNING 1
            )
            SELECT EXISTS (SELECT FROM finished)
        $$;
    """)
    for signature in (
        "veriq_queue_claim(uuid)",
        "veriq_queue_heartbeat(uuid,uuid,integer)",
        "veriq_queue_finish(uuid,uuid,integer,boolean)",
    ):
        op.execute(f"""
            ALTER FUNCTION public.{signature} OWNER TO veriq_queue_store;
            REVOKE ALL ON FUNCTION public.{signature} FROM PUBLIC;
            GRANT EXECUTE ON FUNCTION public.{signature} TO veriq_worker;
        """)


def downgrade() -> None:
    raise RuntimeError("Downgrading 0020 would discard active queue leases")
