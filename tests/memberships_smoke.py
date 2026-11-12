"""Verify identity migrations and TEN-01 in an isolated Compose project."""

import os
import subprocess
from pathlib import Path
from uuid import uuid4

COMPOSE = ["docker", "compose", "-f", "compose.yaml", "-f", "compose.dev.yaml"]
CHECKS = Path(__file__).with_name("membership_checks.py")
TENANT_CHECKS = Path(__file__).with_name("tenant_checks.py")
AUTH_RATE_CHECKS = Path(__file__).with_name("auth_rate_checks.py")
SESSION_CHECKS = Path(__file__).with_name("session_checks.py")
CHECK_SERVICE_ROLE = """
import sys
from sqlalchemy import text
from veriq.database import create_database_engine

with create_database_engine().connect() as connection:
    assert connection.execute(text("SELECT current_user")).scalar_one() == sys.argv[1]
"""


def compose(*args: str, stdin: str | None = None) -> None:
    subprocess.run(
        [*COMPOSE, *args], input=stdin, encoding="utf-8", check=True, timeout=120
    )


def database(sql: str) -> None:
    compose(
        "exec",
        "-T",
        "postgres",
        "psql",
        "-U",
        "veriq_dev",
        "-d",
        "postgres",
        "-v",
        "ON_ERROR_STOP=1",
        "-c",
        sql,
    )


def scratch(database_name: str, *args: str, stdin: str | None = None) -> None:
    compose(
        "run",
        "--no-deps",
        "--rm",
        "-T",
        "-e",
        f"VERIQ_DB_NAME={database_name}",
        "migrate",
        *args,
        stdin=stdin,
    )


def main() -> None:
    if os.environ.get("COMPOSE_PROJECT_NAME") not in {
        "veriq-ci",
        "veriq-worker-smoke-local",
    }:
        raise SystemExit("Use the dedicated local or CI Compose project")
    database_name = f"memberships_test_{uuid4().hex}"
    checks = CHECKS.read_text(encoding="utf-8")
    for service, role in (("api", "veriq_api"), ("worker", "veriq_worker")):
        compose("exec", "-T", service, "python", "-c", CHECK_SERVICE_ROLE, role)
    # The running Compose stack has already migrated a fresh database in CI.
    compose(
        "run",
        "--no-deps",
        "--rm",
        "-T",
        "migrate",
        "alembic",
        "current",
        "--check-heads",
    )
    database(f"CREATE DATABASE {database_name}")
    try:
        scratch(database_name, "alembic", "upgrade", "head")
        scratch(database_name, "alembic", "current", "--check-heads")
        scratch(database_name, "alembic", "downgrade", "0002")
        scratch(database_name, "python", "-", "seed", stdin=checks)
        scratch(database_name, "alembic", "upgrade", "0003")
        scratch(database_name, "python", "-", "upgrade", stdin=checks)
        scratch(database_name, "alembic", "upgrade", "0004")
        scratch(database_name, "python", "-", "legacy-grants", stdin=checks)
        scratch(database_name, "alembic", "upgrade", "0005")
        scratch(database_name, "alembic", "upgrade", "0006")
        scratch(database_name, "alembic", "upgrade", "0007")
        scratch(database_name, "alembic", "upgrade", "head")
        scratch(database_name, "alembic", "current", "--check-heads")
        compose("restart", "postgres")
        compose("up", "--wait", "--wait-timeout", "90")
        scratch(database_name, "python", "-", "roles", stdin=checks)
        scratch(
            database_name,
            "python",
            "-",
            stdin=TENANT_CHECKS.read_text(encoding="utf-8"),
        )
        rate_checks = AUTH_RATE_CHECKS.read_text(encoding="utf-8")
        compose("exec", "-T", "api", "python", "-", stdin=rate_checks)
        compose("stop", "redis")
        try:
            compose("exec", "-T", "api", "python", "-", "outage", stdin=rate_checks)
            scratch(
                database_name,
                "python",
                "-",
                stdin=SESSION_CHECKS.read_text(encoding="utf-8"),
            )
        finally:
            compose("start", "redis")
            compose("up", "--wait", "--wait-timeout", "90")
    finally:
        database(f"DROP DATABASE {database_name}")
    print(
        "Identity smoke: fresh install, upgrades through 0008, runtime roles, TEN-01 and sessions passed."
    )


if __name__ == "__main__":
    main()
