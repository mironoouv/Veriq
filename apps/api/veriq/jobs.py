import asyncio
import logging
from collections.abc import Callable
from threading import Event, Thread
from uuid import UUID, uuid4

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


class LeaseLost(RuntimeError):
    """The handler must roll back because its claim is no longer authoritative."""


def process_next(
    engine: Engine,
    probe: Callable[[Connection], None] = run_probe,
    *,
    owner: UUID | None = None,
) -> bool:
    owner = owner or uuid4()
    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL statement_timeout = '3s'")
        row = connection.execute(
            text("SELECT * FROM public.veriq_queue_claim(:owner)"), {"owner": owner}
        ).first()
    if row is None:
        return False

    params = {"id": row.id, "owner": owner, "token": row.attempts}
    stopped, lost = Event(), Event()

    def heartbeat() -> None:
        while not stopped.wait(3):
            try:
                with engine.begin() as connection:
                    connection.exec_driver_sql("SET LOCAL statement_timeout = '3s'")
                    renewed = connection.execute(
                        text("SELECT public.veriq_queue_heartbeat(:id,:owner,:token)"),
                        params,
                    ).scalar_one()
                if renewed:
                    continue
            except Exception:  # noqa: BLE001 - any failed renewal invalidates local ownership
                LOG.warning("Background lease renewal unavailable")
            lost.set()
            return

    renewal = Thread(target=heartbeat, name="veriq-queue-heartbeat")
    renewal.start()
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL statement_timeout = '3s'")
            succeeded = False
            if row.kind == "probe":
                try:
                    with connection.begin_nested():
                        probe(connection)
                    succeeded = True
                except SQLAlchemyError:
                    LOG.warning("Background probe failed (attempt %d)", row.attempts)
            else:
                LOG.warning("Unknown background task kind rejected")

            if (
                lost.is_set()
                or not connection.execute(
                    text(
                        "SELECT public.veriq_queue_finish(:id,:owner,:token,:success)"
                    ),
                    {**params, "success": succeeded},
                ).scalar_one()
            ):
                raise LeaseLost
    except LeaseLost:
        LOG.warning("Background lease lost; handler transaction rolled back")
    finally:
        stopped.set()
        renewal.join()
    return True
