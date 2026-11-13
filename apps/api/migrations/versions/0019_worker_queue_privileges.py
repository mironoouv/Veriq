"""Confine worker queue access to transaction-bound commands."""

from alembic import op

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        DO $$ BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='veriq_queue_store') THEN
                CREATE ROLE veriq_queue_store NOLOGIN NOINHERIT NOSUPERUSER
                    NOCREATEROLE NOCREATEDB NOBYPASSRLS;
            END IF;
        END $$;
        GRANT USAGE ON SCHEMA public TO veriq_queue_store;
        ALTER TABLE public.background_jobs ADD COLUMN claim_xid xid8;
        GRANT SELECT, INSERT (id,kind), UPDATE (claim_xid,status,attempts,available_at)
            ON public.background_jobs TO veriq_queue_store;
        REVOKE SELECT, INSERT, UPDATE ON public.background_jobs FROM veriq_worker;

        CREATE FUNCTION public.veriq_queue_enqueue(p_id uuid) RETURNS void
        LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
            INSERT INTO public.background_jobs(id,kind) VALUES (p_id,'probe')
            ON CONFLICT (id) DO NOTHING
        $$;

        CREATE FUNCTION public.veriq_queue_claim()
        RETURNS TABLE(id uuid,kind text,attempts integer)
        LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
            WITH candidate AS (
                SELECT j.id FROM public.background_jobs j
                WHERE j.status='pending' AND j.available_at<=statement_timestamp()
                  AND (j.claim_xid IS NULL OR j.claim_xid<>pg_current_xact_id())
                ORDER BY j.available_at,j.id LIMIT 1 FOR UPDATE SKIP LOCKED
            )
            UPDATE public.background_jobs j SET claim_xid=pg_current_xact_id()
            FROM candidate c WHERE j.id=c.id
            RETURNING j.id,j.kind::text,j.attempts
        $$;

        CREATE FUNCTION public.veriq_queue_finish(p_id uuid,p_success boolean) RETURNS boolean
        LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
            WITH finished AS (
                UPDATE public.background_jobs j SET
                    attempts=least(j.attempts+1,3),
                    status=CASE WHEN j.kind='probe' AND p_success THEN 'succeeded'
                                WHEN j.kind='probe' AND j.attempts<2 THEN 'pending'
                                ELSE 'failed' END,
                    available_at=clock_timestamp() + make_interval(secs =>
                        CASE WHEN j.kind='probe' AND NOT p_success AND j.attempts<2
                             THEN power(2,j.attempts+1) ELSE 0 END),
                    claim_xid=NULL
                WHERE j.id=p_id AND j.status='pending' AND p_success IS NOT NULL
                  AND j.claim_xid=pg_current_xact_id()
                RETURNING 1
            )
            SELECT EXISTS (SELECT FROM finished)
        $$;
    """)
    for signature in (
        "veriq_queue_enqueue(uuid)",
        "veriq_queue_claim()",
        "veriq_queue_finish(uuid,boolean)",
    ):
        op.execute(f"""
            ALTER FUNCTION public.{signature} OWNER TO veriq_queue_store;
            REVOKE ALL ON FUNCTION public.{signature} FROM PUBLIC;
            GRANT EXECUTE ON FUNCTION public.{signature} TO veriq_worker;
        """)


def downgrade() -> None:
    raise RuntimeError("Downgrading 0019 would restore broad worker queue privileges")
