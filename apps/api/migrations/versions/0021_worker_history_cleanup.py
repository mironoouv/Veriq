"""Keep seven days of terminal queue history without forgetting job IDs."""

from alembic import op

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        SET LOCAL lock_timeout = '5s';
        LOCK TABLE public.background_jobs IN ACCESS EXCLUSIVE MODE;
        ALTER TABLE public.background_jobs ADD COLUMN finished_at timestamptz;
        -- Legacy rows have no authoritative completion timestamp.
        UPDATE public.background_jobs SET finished_at=statement_timestamp()
            WHERE status IN ('succeeded','failed');
        ALTER TABLE public.background_jobs ADD CHECK (
            (finished_at IS NOT NULL) = (status IN ('succeeded','failed'))
        );
        CREATE INDEX ix_background_jobs_finished
            ON public.background_jobs(finished_at,id) WHERE finished_at IS NOT NULL;

        CREATE FUNCTION public.veriq_queue_stamp_finish() RETURNS trigger
        LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
        BEGIN
            IF NEW.status IN ('succeeded','failed') THEN
                NEW.finished_at := clock_timestamp();
            END IF;
            RETURN NEW;
        END $$;
        REVOKE ALL ON FUNCTION public.veriq_queue_stamp_finish() FROM PUBLIC;
        CREATE TRIGGER queue_stamp_finish BEFORE UPDATE OF status ON public.background_jobs
            FOR EACH ROW WHEN (OLD.status IS DISTINCT FROM NEW.status)
            EXECUTE FUNCTION public.veriq_queue_stamp_finish();

        CREATE TABLE public.background_job_keys (id uuid PRIMARY KEY);
        INSERT INTO public.background_job_keys SELECT id FROM public.background_jobs;
        GRANT SELECT (id), INSERT (id) ON public.background_job_keys TO veriq_queue_store;
        CREATE OR REPLACE FUNCTION public.veriq_queue_enqueue(p_id uuid) RETURNS void
        LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
            WITH registered AS (
                INSERT INTO public.background_job_keys(id) VALUES (p_id)
                ON CONFLICT DO NOTHING RETURNING id
            )
            INSERT INTO public.background_jobs(id,kind) SELECT id,'probe' FROM registered
        $$;

        DO $$ BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='veriq_queue_purger') THEN
                CREATE ROLE veriq_queue_purger NOLOGIN NOINHERIT NOSUPERUSER
                    NOCREATEROLE NOCREATEDB NOBYPASSRLS;
            END IF;
        END $$;
        GRANT USAGE ON SCHEMA public TO veriq_queue_purger;
        GRANT SELECT (id,status,finished_at,lease_owner,lease_until), UPDATE (id), DELETE
            ON public.background_jobs TO veriq_queue_purger;
        CREATE FUNCTION public.veriq_queue_purge() RETURNS integer
        LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
            WITH candidates AS (
                SELECT id FROM public.background_jobs
                WHERE finished_at<=statement_timestamp()-interval '168 hours'
                  AND status IN ('succeeded','failed') AND lease_owner IS NULL AND lease_until IS NULL
                ORDER BY finished_at,id LIMIT 100 FOR UPDATE SKIP LOCKED
            ), removed AS (
                DELETE FROM public.background_jobs j USING candidates c WHERE j.id=c.id RETURNING 1
            )
            SELECT count(*)::integer FROM removed
        $$;
        ALTER FUNCTION public.veriq_queue_purge() OWNER TO veriq_queue_purger;
        REVOKE ALL ON FUNCTION public.veriq_queue_purge() FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION public.veriq_queue_purge() TO veriq_worker;
    """)


def downgrade() -> None:
    raise RuntimeError("Downgrading 0021 would discard durable queue deduplication")
