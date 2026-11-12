import logging
from collections.abc import Callable
from uuid import UUID

from redis import Redis
from redis.exceptions import RedisError
from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import SQLAlchemyError

LOG = logging.getLogger(__name__)
WAKE_QUEUE = "veriq:background:wake"
MAX_ATTEMPTS = 3


def enqueue_probe(engine: Engine, redis: Redis, job_id: UUID) -> None:
    with engine.begin() as connection:
        connection.execute(
            text("""
            INSERT INTO background_jobs (id, kind) VALUES (:id, 'probe')
            ON CONFLICT (id) DO NOTHING
        """),
            {"id": job_id},
        )
    try:
        with redis.pipeline() as pipe:
            pipe.lpush(WAKE_QUEUE, "wake")
            pipe.ltrim(WAKE_QUEUE, 0, 127)
            pipe.execute()
    except RedisError:
        LOG.warning(
            "Background wake-up unavailable; PostgreSQL polling will deliver the job"
        )


def run_probe(connection: Connection) -> None:
    connection.execute(text("SELECT 1"))


def process_next(
    engine: Engine, probe: Callable[[Connection], None] = run_probe
) -> bool:
    with engine.begin() as connection:
        connection.execute(text("SET LOCAL statement_timeout = '3s'"))
        row = connection.execute(
            text("""
            SELECT id, kind, attempts FROM background_jobs
            WHERE status = 'pending' AND available_at <= now()
            ORDER BY available_at, id LIMIT 1 FOR UPDATE SKIP LOCKED
        """)
        ).first()
        if row is None:
            return False

        attempts = row.attempts + 1
        status = "failed"
        if row.kind == "probe":
            try:
                with connection.begin_nested():
                    probe(connection)
                status = "succeeded"
            except SQLAlchemyError:
                status = "pending" if attempts < MAX_ATTEMPTS else "failed"
                LOG.warning("Background probe failed (attempt %d)", attempts)
        else:
            LOG.warning("Unknown background task kind rejected")

        connection.execute(
            text("""
            UPDATE background_jobs
            SET status = :status, attempts = :attempts,
                available_at = clock_timestamp() + make_interval(secs => :delay)
            WHERE id = :id
        """),
            {
                "status": status,
                "attempts": attempts,
                "delay": 2**attempts if status == "pending" else 0,
                "id": row.id,
            },
        )
    return True
