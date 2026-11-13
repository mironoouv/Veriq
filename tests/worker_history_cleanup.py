"""Retention boundary and concurrent cleanup under real PostgreSQL logins."""

import os
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import uuid4

from sqlalchemy import text
from veriq.database import create_database_engine, database_url
from veriq.worker import purge_queue_history


def main():
    owner = create_database_engine()
    worker = create_database_engine(
        database_url().set(
            username="veriq_worker", password=os.environ["VERIQ_WORKER_DB_PASSWORD"]
        )
    )
    with owner.begin() as db:
        assert db.exec_driver_sql("SHOW server_version_num").scalar_one() == "170011"
        db.exec_driver_sql("""
            INSERT INTO background_job_keys SELECT gen_random_uuid() FROM generate_series(1,205);
            INSERT INTO background_jobs(id,kind,status,finished_at)
            SELECT id,'probe','succeeded',now()-interval '8 days' FROM background_job_keys;
            INSERT INTO background_jobs(id,kind,status,finished_at,available_at)
            VALUES (gen_random_uuid(),'probe','failed',now()-interval '6 days',now()),
                   (gen_random_uuid(),'probe','pending',NULL,now()-interval '90 days');
            INSERT INTO background_jobs(id,kind,status,attempts,lease_owner,lease_until,available_at)
            VALUES (gen_random_uuid(),'probe','running',3,gen_random_uuid(),
                    now()-interval '8 days',now()-interval '90 days');
        """)
        previous = db.exec_driver_sql(
            "SELECT id FROM background_job_keys LIMIT 1"
        ).scalar_one()
    barrier = Barrier(2)

    def purge(_):
        with worker.begin() as db:
            assert (
                db.exec_driver_sql("SELECT session_user").scalar_one() == "veriq_worker"
            )
            barrier.wait(timeout=10)
            return db.exec_driver_sql("SELECT public.veriq_queue_purge()").scalar_one()

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert list(pool.map(purge, range(2))) == [100, 100]
    with worker.begin() as db:
        assert db.exec_driver_sql("SELECT public.veriq_queue_purge()").scalar_one() == 5
        assert db.exec_driver_sql("SELECT public.veriq_queue_purge()").scalar_one() == 0
        db.execute(text("SELECT public.veriq_queue_enqueue(:id)"), {"id": previous})
    with owner.begin() as db:
        assert db.exec_driver_sql(
            "SELECT status FROM background_jobs ORDER BY status"
        ).scalars().all() == ["failed", "pending", "running"]
        db.exec_driver_sql("""
            DO $$ BEGIN
                INSERT INTO public.background_jobs(id,kind,status,finished_at)
                VALUES (gen_random_uuid(),'probe','failed',statement_timestamp()-interval '168 hours');
                IF public.veriq_queue_purge()<>1 THEN
                    RAISE EXCEPTION 'Exact retention boundary was not purged';
                END IF;
            END $$;
        """)
        db.exec_driver_sql("""
            CREATE FUNCTION test_cleanup_failure() RETURNS trigger LANGUAGE plpgsql AS
            $$ BEGIN RAISE EXCEPTION 'test cleanup failure'; END $$;
            CREATE TRIGGER test_cleanup_failure BEFORE DELETE ON background_jobs
            FOR EACH ROW EXECUTE FUNCTION test_cleanup_failure();
            INSERT INTO background_jobs(id,kind,status,finished_at)
            VALUES (gen_random_uuid(),'probe','failed',now()-interval '8 days');
        """)
    purge_queue_history(worker)
    with owner.begin() as db:
        assert (
            db.exec_driver_sql("SELECT count(*) FROM background_jobs").scalar_one() == 4
        )
        db.exec_driver_sql("DROP TRIGGER test_cleanup_failure ON background_jobs")
    with worker.begin() as db:
        lease_owner = uuid4()
        claim = db.execute(
            text("SELECT * FROM public.veriq_queue_claim(:owner)"),
            {"owner": lease_owner},
        ).one()
        assert db.execute(
            text("SELECT public.veriq_queue_finish(:id,:owner,:token,true)"),
            {"id": claim.id, "owner": lease_owner, "token": claim.attempts},
        ).scalar_one()
        assert db.exec_driver_sql("SELECT public.veriq_queue_purge()").scalar_one() == 1
    with owner.begin() as db:
        assert (
            db.exec_driver_sql("""
            SELECT count(*) FROM background_jobs
            WHERE status IN ('failed','succeeded') AND finished_at > now()-interval '1 minute'
        """).scalar_one()
            == 2
        )
    print(
        "Retention: cutoff, bounded concurrent batches, deduplication, error isolation, finish and recovery passed"
    )


if __name__ == "__main__":
    main()
