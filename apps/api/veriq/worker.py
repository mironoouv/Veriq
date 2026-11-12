import argparse
import logging
import signal
from pathlib import Path
from threading import Event
from time import time
from types import FrameType
from uuid import UUID

from redis.exceptions import RedisError
from sqlalchemy.exc import SQLAlchemyError

from veriq.database import create_database_engine
from veriq.jobs import WAKE_QUEUE, enqueue_probe, process_next
from veriq.redis_client import create_redis

HEARTBEAT = Path("/tmp/veriq-worker-heartbeat")
LOG = logging.getLogger(__name__)


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("run")
    commands.add_parser("health")
    enqueue = commands.add_parser("enqueue-probe")
    enqueue.add_argument("id", type=UUID)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    if args.command == "health":
        try:
            return int(time() - HEARTBEAT.stat().st_mtime >= 15)
        except OSError:
            return 1

    engine = create_database_engine()
    redis = create_redis()
    try:
        if args.command == "enqueue-probe":
            enqueue_probe(engine, redis, args.id)
            return 0

        stopped = Event()

        def stop(signum: int, frame: FrameType | None) -> None:
            stopped.set()

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        HEARTBEAT.unlink(missing_ok=True)
        while not stopped.is_set():
            try:
                processed = process_next(engine)
                HEARTBEAT.touch()
            except SQLAlchemyError:
                LOG.warning("Background database operation unavailable")
                stopped.wait(1)
                continue
            if not processed:
                try:
                    redis.blpop([WAKE_QUEUE], timeout=1)
                except RedisError:
                    stopped.wait(1)
        HEARTBEAT.unlink(missing_ok=True)
        return 0
    finally:
        redis.close()
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
