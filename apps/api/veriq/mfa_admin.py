"""Offline test enrollment after independently verified operator approval."""

import argparse
import os
from pathlib import Path
from uuid import UUID

from sqlalchemy.exc import SQLAlchemyError

from veriq.auth_audit import RequestContext
from veriq.database import create_database_engine, database_url
from veriq.mfa import Mfa
from veriq.mfa_crypto import FactorKeys
from veriq.sessions import Sessions
from veriq.tenant_access import AccessDenied


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--user", required=True, type=UUID)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if os.environ.get("VERIQ_ENV") != "test" or os.name != "posix":
        raise SystemExit("Enrollment must run on the isolated Linux test host")
    engine = create_database_engine(
        database_url().set(
            username="veriq_mfa_verifier",
            password=os.environ["VERIQ_TEST_MFA_DB_PASSWORD"],
        )
    )
    try:
        path: Path = args.output
        if path.parent.stat().st_mode & 0o077:
            raise SystemExit("Enrollment output directory must be private")
        service = Mfa(
            engine,
            Sessions(engine),
            FactorKeys.load(Path(os.environ["VERIQ_TEST_MFA_KEYRING"])),
        )
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="ascii") as output:
                output.write(
                    service.prepare_enrollment(args.user, RequestContext.new()) + "\n"
                )
        except (OSError, SQLAlchemyError, AccessDenied):
            path.unlink(missing_ok=True)
            raise SystemExit("Enrollment failed") from None
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
