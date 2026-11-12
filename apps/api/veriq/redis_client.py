import asyncio
import os
from typing import cast

from redis.asyncio import Redis
from redis.backoff import NoBackoff
from redis.retry import Retry


def create_redis() -> Redis:
    return cast(
        Redis,
        Redis.from_url(
            os.environ["VERIQ_REDIS_URL"],
            socket_connect_timeout=1,
            socket_timeout=2,
            retry=Retry(NoBackoff(), 0),
        ),
    )


async def ping_redis(redis: Redis) -> None:
    async with asyncio.timeout(2):
        await redis.ping()
