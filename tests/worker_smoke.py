"""Run only against a disposable, running Foundation Compose project."""

import json
import os
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.request import urlopen
from uuid import uuid4

BASE = f"http://127.0.0.1:{int(os.environ.get('VERIQ_WEB_PORT', '5173'))}/api/v1/health"
COMPOSE = ["docker", "compose", "-f", "compose.yaml", "-f", "compose.dev.yaml"]


def compose(*args: str) -> str:
    return subprocess.check_output([*COMPOSE, *args], text=True, timeout=120).strip()


def database(sql: str) -> str:
    return compose(
        "exec",
        "-T",
        "postgres",
        "psql",
        "-U",
        "veriq_dev",
        "-d",
        "veriq",
        "-v",
        "ON_ERROR_STOP=1",
        "-Atc",
        sql,
    )


def enqueue(job_id: str) -> None:
    compose(
        "run",
        "--no-deps",
        "--rm",
        "worker",
        "python",
        "-m",
        "veriq.worker",
        "enqueue-probe",
        job_id,
    )


def health(probe: str) -> int:
    try:
        with urlopen(f"{BASE}/{probe}", timeout=5) as response:
            return response.status if json.load(response) == {"status": "ok"} else 0
    except HTTPError as exc:
        return exc.code
    except URLError:
        return 0


def expect_job(job_id: str, expected: str) -> None:
    for _ in range(40):
        result = database(
            f"SELECT status, attempts FROM background_jobs WHERE id = '{job_id}'"
        )
        if result == expected:
            return
        time.sleep(0.25)
    raise AssertionError(f"Expected {expected}, got {result}")


def main() -> None:
    if not os.environ.get("COMPOSE_PROJECT_NAME", "").startswith("veriq-"):
        raise SystemExit("Set COMPOSE_PROJECT_NAME to a disposable veriq-* project")

    first, second, third = (str(uuid4()) for _ in range(3))
    compose("exec", "-T", "worker", "python", "-m", "veriq.worker", "health")
    assert compose("exec", "-T", "redis", "redis-cli", "ping") == "PONG"
    enqueue(first)
    expect_job(first, "succeeded|1")
    enqueue(first)
    expect_job(first, "succeeded|1")

    compose("stop", "redis")
    try:
        assert health("live") == 200
        assert health("ready") == 503
        enqueue(second)
        expect_job(second, "succeeded|1")
        compose("stop", "worker")
        enqueue(third)
        expect_job(third, "pending|0")

        # Use real statement timeout and savepoint rollback while the regular worker is stopped.
        script = """
from sqlalchemy import text
from veriq.database import create_database_engine
from veriq.jobs import process_next

def fail(connection):
    connection.execute(text("SELECT pg_sleep(5)"))

assert process_next(create_database_engine(), fail)
"""
        compose("run", "--no-deps", "--rm", "worker", "python", "-c", script)
        expect_job(third, "pending|1")
    finally:
        compose("up", "--wait", "--wait-timeout", "90")

    expect_job(third, "succeeded|2")
    assert health("ready") == 200
    expect_job(first, "succeeded|1")
    print(
        "Worker smoke: readiness, duplicate delivery, timeout, retry, Redis outage and restart passed."
    )


if __name__ == "__main__":
    main()
