"""Verify identity migrations and TEN-01 in an isolated Compose project."""

import os
import subprocess
from pathlib import Path
from uuid import uuid4

COMPOSE = ["docker", "compose", "-f", "compose.yaml", "-f", "compose.dev.yaml"]
CHECKS = Path(__file__).with_name("membership_checks.py")
TENANT_CHECKS = Path(__file__).with_name("tenant_checks.py")
REGISTRATION_CHECKS = Path(__file__).with_name("registration_checks.py")
AUTH_RATE_CHECKS = Path(__file__).with_name("auth_rate_checks.py")
MFA_RECOVERY_CHECKS = Path(__file__).with_name("mfa_recovery_checks.py")
CATALOG_CHECKS = Path(__file__).with_name("academic_catalog_checks.py")
IMPORT_CHECKS = Path(__file__).with_name("bulk_import_checks.py")
JOINING_CHECKS = Path(__file__).with_name("organization_joining_checks.py")
PASSWORD_CHECKS = Path(__file__).with_name("password_recovery_checks.py")
MFA_CHECKS = Path(__file__).with_name("mfa_checks.py")
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


def registration(database_name: str, *args: str) -> None:
    environment = {
        **os.environ,
        "VERIQ_DB_PASSWORD_FOR_TEST": os.environ["VERIQ_DB_PASSWORD"],
    }
    subprocess.run(
        [
            *COMPOSE,
            "exec",
            "-T",
            "-e",
            f"VERIQ_DB_NAME={database_name}",
            "-e",
            "VERIQ_DB_PASSWORD_FOR_TEST",
            "-e",
            "VERIQ_WORKER_DB_PASSWORD",
            "api",
            "python",
            "-",
            *args,
        ],
        env=environment,
        input=REGISTRATION_CHECKS.read_text(encoding="utf-8"),
        encoding="utf-8",
        check=True,
        timeout=120,
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
        scratch(database_name, "alembic", "upgrade", "0008")
        scratch(database_name, "alembic", "upgrade", "0009")
        scratch(database_name, "alembic", "upgrade", "0010")
        scratch(database_name, "alembic", "upgrade", "0011")
        scratch(database_name, "alembic", "upgrade", "0012")
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
        registration(database_name)
        scratch(
            database_name, "python", "-", stdin=MFA_CHECKS.read_text(encoding="utf-8")
        )
        rate_checks = AUTH_RATE_CHECKS.read_text(encoding="utf-8")
        compose("exec", "-T", "api", "python", "-", stdin=rate_checks)
        compose("stop", "redis")
        try:
            compose("exec", "-T", "api", "python", "-", "outage", stdin=rate_checks)
            registration(database_name, "outage")
            scratch(
                database_name,
                "python",
                "-",
                stdin=SESSION_CHECKS.read_text(encoding="utf-8"),
            )
        finally:
            compose("start", "redis")
            compose("up", "--wait", "--wait-timeout", "90")
        scratch(
            database_name,
            "python",
            "-",
            stdin=PASSWORD_CHECKS.read_text(encoding="utf-8"),
        )
        scratch(
            database_name,
            "python",
            "-",
            stdin=MFA_RECOVERY_CHECKS.read_text(encoding="utf-8"),
        )
    finally:
        database(f"DROP DATABASE {database_name}")
    joining_db = f"joining_test_{uuid4().hex}"
    joining_checks = JOINING_CHECKS.read_text(encoding="utf-8")
    database(f"CREATE DATABASE {joining_db}")
    try:
        scratch(joining_db, "alembic", "upgrade", "0013")
        scratch(joining_db, "python", "-", "seed", stdin=joining_checks)
        scratch(joining_db, "alembic", "upgrade", "head")
        scratch(joining_db, "alembic", "current", "--check-heads")
        scratch(joining_db, "python", "-", stdin=joining_checks)
    finally:
        database(f"DROP DATABASE {joining_db}")
    import_db = f"import_test_{uuid4().hex}"
    import_checks = IMPORT_CHECKS.read_text(encoding="utf-8")
    database(f"CREATE DATABASE {import_db}")
    try:
        scratch(import_db, "alembic", "upgrade", "0014")
        scratch(import_db, "python", "-", "seed", stdin=import_checks)
        scratch(import_db, "alembic", "upgrade", "head")
        scratch(import_db, "alembic", "current", "--check-heads")
        scratch(import_db, "python", "-", stdin=import_checks)
    finally:
        database(f"DROP DATABASE {import_db}")
    catalog_db = f"catalog_test_{uuid4().hex}"
    catalog_checks = CATALOG_CHECKS.read_text(encoding="utf-8")
    database(f"CREATE DATABASE {catalog_db}")
    try:
        scratch(catalog_db, "alembic", "upgrade", "0015")
        scratch(catalog_db, "python", "-", "seed", stdin=catalog_checks)
        scratch(catalog_db, "alembic", "upgrade", "head")
        scratch(catalog_db, "alembic", "current", "--check-heads")
        scratch(catalog_db, "python", "-", stdin=catalog_checks)
    finally:
        database(f"DROP DATABASE {catalog_db}")
    print(
        "Identity smoke: fresh install, upgrades through 0016, runtime roles, TEN-01 and sessions passed."
    )


if __name__ == "__main__":
    main()
