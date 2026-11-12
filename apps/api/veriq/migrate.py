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
    verifier = os.environ.get("VERIQ_TEST_LOGIN_VERIFIER_PASSWORD", "")
    issuer = os.environ.get("VERIQ_TEST_LOGIN_ISSUER_PASSWORD", "")
    if verifier or issuer:
        credentials.update(
            veriq_password_verifier=verifier, veriq_browser_issuer=issuer
        )
    mfa = os.environ.get("VERIQ_TEST_MFA_DB_PASSWORD", "")
    if mfa:
        credentials["veriq_mfa_verifier"] = mfa
    if (
        "" in credentials.values()
        or len({*credentials.values(), os.environ["VERIQ_DB_PASSWORD"]})
        != len(credentials) + 1
    ):
        raise SystemExit("Database roles require distinct credentials")
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
