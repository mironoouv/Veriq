"""Compose migration entry point. Runtime containers receive separate credentials."""

import os

from alembic import command
from alembic.config import Config
from psycopg import Connection as PsycopgConnection
from psycopg import Error as PsycopgError
from psycopg import sql
from sqlalchemy.exc import SQLAlchemyError

from veriq.database import create_database_engine


def main() -> None:
    credentials = {
        "veriq_api": os.environ["VERIQ_API_DB_PASSWORD"],
        "veriq_worker": os.environ["VERIQ_WORKER_DB_PASSWORD"],
    }
    if (
        "" in credentials.values()
        or len({*credentials.values(), os.environ["VERIQ_DB_PASSWORD"]}) != 3
    ):
        raise SystemExit(
            "Migration, API and worker require distinct database credentials"
        )
    command.upgrade(Config("alembic.ini"), "head")
    engine = create_database_engine()
    try:
        with engine.begin() as connection:
            driver = connection.connection.driver_connection
            if not isinstance(driver, PsycopgConnection):
                raise SystemExit("Database role provisioning requires psycopg")
            for role, password in credentials.items():
                verifier = driver.pgconn.encrypt_password(
                    password.encode(), role.encode(), b"scram-sha-256"
                ).decode("ascii")
                driver.execute(
                    sql.SQL("ALTER ROLE {} LOGIN PASSWORD {}").format(
                        sql.Identifier(role), sql.Literal(verifier)
                    )
                )
    except (SQLAlchemyError, PsycopgError):
        raise SystemExit("Database runtime role provisioning failed") from None
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
