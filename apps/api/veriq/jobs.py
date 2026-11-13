import asyncio
import logging
from collections.abc import Callable
from uuid import UUID

from redis.asyncio import Redis
from redis.exceptions import RedisError
from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import SQLAlchemyError

LOG = logging.getLogger(__name__)
WAKE_QUEUE = "veriq:background:wake"


async def enqueue_probe(engine: Engine, redis: Redis, job_id: UUID) -> None:
    with engine.begin() as connection:
        connection.execute(
            text("SELECT public.veriq_queue_enqueue(:id)"),
            {"id": job_id},
        )
    try:
        async with asyncio.timeout(2), redis.pipeline() as pipe:
            pipe.lpush(WAKE_QUEUE, "wake")
            pipe.ltrim(WAKE_QUEUE, 0, 127)
            await pipe.execute()
    except (RedisError, TimeoutError):
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
            text("SELECT * FROM public.veriq_queue_claim()")
        ).first()
        if row is None:
            return False

        attempts = row.attempts + 1
        succeeded = False
        if row.kind == "probe":
            try:
                with connection.begin_nested():
                    probe(connection)
                succeeded = True
            except SQLAlchemyError:
                LOG.warning("Background probe failed (attempt %d)", attempts)
        else:
            LOG.warning("Unknown background task kind rejected")

        finished = connection.execute(
            text("SELECT public.veriq_queue_finish(:id,:success)"),
            {"id": row.id, "success": succeeded},
        ).scalar_one()
        if not finished:
            raise RuntimeError("Queue claim could not be completed")
    return True
