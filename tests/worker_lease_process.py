"""Exercise real worker process loss with the production lease durations."""

import os
import signal
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from time import monotonic, sleep
from uuid import uuid4

from sqlalchemy import text
from veriq.database import create_database_engine, database_url
from veriq.jobs import process_next

CHILD = """
import signal
import sys
from uuid import UUID
from veriq.database import create_database_engine
from veriq.jobs import process_next

def hold(connection):
    while True:
        connection.exec_driver_sql("SELECT pg_sleep(1)")

engine = create_database_engine()
try:
    process_next(engine, hold, owner=UUID(sys.argv[1]))
finally:
    engine.dispose()
"""


def wait_until(predicate, timeout=25):
    deadline = monotonic() + timeout
    while monotonic() < deadline:
        result = predicate()
        if result:
            return result
        sleep(0.05)
    raise AssertionError("Timed out waiting for queue state")


def main():
    owner = create_database_engine()
    worker = create_database_engine(
        database_url().set(
            username="veriq_worker", password=os.environ["VERIQ_WORKER_DB_PASSWORD"]
        )
    )

    def execute(engine, sql, **params):
        with engine.begin() as conn:
            result = conn.execute(text(sql), params)
            return result.first() if result.returns_rows else None

    assert execute(worker, "SELECT session_user") == ("veriq_worker",)
    assert execute(worker, "SHOW server_version_num") == ("170011",)

    def state(job):
        return execute(
            owner,
            """
            SELECT status,attempts,lease_owner,lease_until,lease_until<=clock_timestamp()
            FROM background_jobs WHERE id=:id
        """,
            id=job,
        )

    def enqueue():
        job = uuid4()
        execute(worker, "SELECT public.veriq_queue_enqueue(:id)", id=job)
        return job

    def kill_claim(job, attempt, *, check_heartbeat=False):
        worker_id = uuid4()
        child = subprocess.Popen(
            [sys.executable, "-c", CHILD, str(worker_id)],
            env={
                **os.environ,
                "VERIQ_DB_USER": "veriq_worker",
                "VERIQ_DB_PASSWORD": os.environ["VERIQ_WORKER_DB_PASSWORD"],
            },
        )
        try:

            def running():
                assert child.poll() is None
                row = state(job)
                return row if row[:3] == ("running", attempt, worker_id) else None

            initial = wait_until(running)
            if check_heartbeat:
                wait_until(lambda: running() and state(job)[3] > initial[3])
        finally:
            child.kill()
            assert child.wait(timeout=5) == -signal.SIGKILL
        assert state(job)[:3] == ("running", attempt, worker_id)
        wait_until(lambda: state(job)[4])
        return worker_id

    def claim(worker_id):
        return execute(
            worker, "SELECT * FROM public.veriq_queue_claim(:owner)", owner=worker_id
        )

    job = enqueue()
    old = kill_claim(job, 1, check_heartbeat=True)
    barrier = Barrier(2)
    candidates = (uuid4(), uuid4())

    def compete(worker_id):
        barrier.wait(timeout=5)
        return worker_id, claim(worker_id)

    # Recovery delay is measured by PostgreSQL, including the retry backoff.
    wait_until(
        lambda: execute(
            owner,
            """
        SELECT clock_timestamp() >= lease_until + interval '2 seconds'
        FROM background_jobs WHERE id=:id
    """,
            id=job,
        )[0]
    )
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(compete, candidates))
    winners = [(candidate, row) for candidate, row in results if row is not None]
    assert len(winners) == 1 and winners[0][1] == (job, "probe", 2)
    winner = winners[0][0]
    assert execute(
        worker, "SELECT public.veriq_queue_heartbeat(:id,:owner,1)", id=job, owner=old
    ) == (False,)
    assert execute(
        worker, "SELECT public.veriq_queue_finish(:id,:owner,1,true)", id=job, owner=old
    ) == (False,)
    assert execute(
        worker,
        "SELECT public.veriq_queue_finish(:id,:owner,2,true)",
        id=job,
        owner=winner,
    ) == (True,)
    assert claim(uuid4()) is None
    print(
        "SIGKILL recovery: real expiry, concurrent claims, fencing and terminal success passed"
    )

    exhausted = enqueue()
    for attempt in range(1, 4):
        if attempt > 1:
            wait_until(
                lambda: execute(
                    owner,
                    """
                SELECT clock_timestamp() >= lease_until + make_interval(secs=>power(2,attempts))
                FROM background_jobs WHERE id=:id
            """,
                    id=exhausted,
                )[0]
            )
        kill_claim(exhausted, attempt)
    assert claim(uuid4()) is None
    assert state(exhausted)[:3] == ("failed", 3, None)
    print(
        "Three SIGKILLs: expired final attempt reached failed without editing the lease"
    )
    rollback_job = enqueue()

    def invalidate_finish(conn):
        conn.exec_driver_sql("CREATE TEMP TABLE lease_rollback_probe (id integer)")
        conn.exec_driver_sql("INSERT INTO lease_rollback_probe VALUES (1)")
        execute(
            owner,
            "UPDATE background_jobs SET lease_until=clock_timestamp() WHERE id=:id",
            id=rollback_job,
        )
        assert state(rollback_job)[4]

    assert process_next(worker, invalidate_finish)
    assert execute(worker, "SELECT to_regclass('pg_temp.lease_rollback_probe')") == (
        None,
    )
    assert state(rollback_job)[:2] == ("running", 1)
    print("Expiry immediately before finish rolled back handler SQL")
    worker.dispose()
    owner.dispose()


if __name__ == "__main__":
    main()
