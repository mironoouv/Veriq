import os

from redis import Redis
from redis.backoff import NoBackoff
from redis.retry import Retry


def create_redis() -> Redis:
    return Redis.from_url(
        os.environ["VERIQ_REDIS_URL"],
        socket_connect_timeout=1,
        socket_timeout=2,
        retry=Retry(NoBackoff(), 0),
    )
