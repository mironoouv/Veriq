"""Bulk import PostgreSQL checks under restricted roles."""

import sys
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from uuid import UUID

from sqlalchemy import Connection, Engine, event, text
from sqlalchemy.exc import DBAPIError
from veriq.auth_credentials import CredentialVerifier
from veriq.bulk_import import BulkImport
from veriq.database import create_database_engine
from veriq.registration_policy import HASHER
from veriq.sessions import Sessions, SessionToken
from veriq.tenant_access import AccessDenied

ORG, OTHER, STAFF, STUDENT, INACTIVE, CLAIMANT, REVOKED = (
    UUID(int=8200 + i) for i in range(7)
)


def role(name: str) -> Engine:
    engine = create_database_engine()

    @event.listens_for(engine, "begin")
    def assume(connection: Connection) -> None:
        connection.exec_driver_sql(f"SET LOCAL ROLE {name}")

    return engine


def query(engine: Engine, statement: str, **parameters: object) -> object:
    with engine.begin() as conn:
        result = conn.execute(text(statement), parameters)
        return result.scalar_one() if result.returns_rows else None


def add_user(owner: Engine, user: UUID, email: str) -> None:
    query(
        owner,
        "INSERT INTO users(id,email_normalized,email_verified_at,password_hash) VALUES (:id,:email,now(),:hash)",
        id=user,
        email=email,
        hash=HASHER.hash("synthetic bulk import fixture passphrase"),
    )


def token(api: Engine, user: UUID, org: UUID | None = None) -> SessionToken:
    verifier = CredentialVerifier(role("veriq_credential_verifier"))
    return Sessions(api, issuer=role("veriq_session_issuer")).issue(
        verifier.confirm(user, 1, mfa_level=int(org is not None), organization_id=org)
    )


def denied(call: Callable[[], object]) -> None:
    try:
        call()
    except AccessDenied:
        return
    raise AssertionError("Expected import denial")


def seed(owner: Engine) -> None:
    for tenant in (ORG, OTHER):
        query(
            owner,
            """
            INSERT INTO organizations(id,slug,display_name,timezone,status)
            VALUES (:org,:slug,'Import fixture','UTC','active')
        """,
            org=tenant,
            slug=tenant.hex,
        )
    for user, email in (
        (STAFF, "staff"),
        (STUDENT, "student"),
        (INACTIVE, "inactive"),
        (REVOKED, "revoked"),
    ):
        add_user(owner, user, f"{email}@example.invalid")
    for member, org, state in (
        (STAFF, ORG, "active"),
        (STUDENT, OTHER, "active"),
        (INACTIVE, ORG, "suspended"),
        (REVOKED, ORG, "revoked"),
    ):
        query(
            owner,
            """
            INSERT INTO organization_memberships (id,organization_id,user_id,status)
            VALUES (:id,:org,:id,:state)
        """,
            id=member,
            org=org,
            state=state,
        )
    query(
        owner,
        "INSERT INTO organization_roles VALUES (:org,:id,'org_admin')",
        org=ORG,
        id=STAFF,
    )
    query(
        owner,
        """
        INSERT INTO membership_roles (organization_id,membership_id,role_id)
        VALUES (:org,:id,:id)
    """,
        org=ORG,
        id=STAFF,
    )


def without_request_ids(batch: dict[str, object]) -> list[dict[str, object]]:
    rows = batch["rows"]
    assert isinstance(rows, list)
    for row in rows:
        assert bool(row["request_id"]) == (row["state"] == "created")
    return [
        {key: value for key, value in row.items() if key != "request_id"}
        for row in rows
    ]


def run(owner: Engine, api: Engine) -> None:
    imports = BulkImport(api)
    staff = token(api, STAFF, ORG)
    csv = (
        b"email\nStudent@Example.Invalid\ninactive@example.invalid\n"
        b"claimant@example.invalid\nstudent@example.invalid\nbad-email\nrevoked@example.invalid\n"
    )
    denied(lambda: imports.upload(ORG, staff, csv, "csv", "email"))
    query(
        owner,
        """
        INSERT INTO mfa_session_assurance(session_id,purpose,verified_at)
        VALUES (:id,'sensitive',clock_timestamp())
    """,
        id=staff._gate(imports.policy).session_id,
    )
    denied(lambda: imports.upload(OTHER, staff, csv, "csv", "email"))
    with ThreadPoolExecutor(max_workers=2) as pool:
        left, right = list(
            pool.map(
                lambda _: imports.upload(ORG, staff, csv, "csv", "email"), range(2)
            )
        )
    assert left == right
    batch = UUID(str(left["batch_id"]))
    version = bytes.fromhex(str(left["version"]))
    assert without_request_ids(left) == [
        {"row": 2, "email": "student@example.invalid", "state": "existing_account"},
        {"row": 3, "email": "inactive@example.invalid", "state": "inactive_membership"},
        {"row": 4, "email": "claimant@example.invalid", "state": "new_email"},
        {"row": 5, "email": None, "state": "duplicate_in_file"},
        {"row": 6, "email": None, "state": "invalid_email"},
        {"row": 7, "email": "revoked@example.invalid", "state": "inactive_membership"},
    ]
    denied(lambda: imports.command(OTHER, staff, "confirm", batch, version))
    denied(lambda: imports.command(ORG, staff, "confirm", batch, bytes(32)))
    with ThreadPoolExecutor(max_workers=2) as pool:
        left, right = list(
            pool.map(
                lambda _: imports.command(ORG, staff, "confirm", batch, version),
                range(2),
            )
        )
    assert left == right and left["confirmed"] is True
    assert without_request_ids(left) == [
        {"row": 2, "email": None, "state": "created"},
        {"row": 3, "email": None, "state": "inactive_membership"},
        {"row": 4, "email": None, "state": "awaiting_verification"},
        {"row": 5, "email": None, "state": "duplicate_in_file"},
        {"row": 6, "email": None, "state": "invalid_email"},
        {"row": 7, "email": None, "state": "inactive_membership"},
    ]
    assert (
        query(
            owner,
            "SELECT count(*) FROM users WHERE email_normalized='claimant@example.invalid'",
        )
        == 0
    )
    assert (
        query(
            owner,
            "SELECT count(*) FROM organization_memberships WHERE user_id=:id",
            id=STUDENT,
        )
        == 2
    )
    assert query(owner, "SELECT count(*) FROM membership_roles") == 1
    assert (
        query(owner, "SELECT count(*) FROM user_import_events WHERE action='confirm'")
        == 1
    )
    add_user(owner, CLAIMANT, "claimant@example.invalid")
    claimant = token(api, CLAIMANT)
    denied(lambda: imports.command(OTHER, claimant, "claim", batch))
    denied(lambda: imports.command(ORG, token(api, STUDENT), "claim", batch))
    query(owner, "UPDATE users SET email_verified_at=NULL WHERE id=:id", id=CLAIMANT)
    denied(lambda: imports.command(ORG, claimant, "claim", batch))
    query(owner, "UPDATE users SET email_verified_at=now() WHERE id=:id", id=CLAIMANT)
    assert imports.command(ORG, claimant, "claim", batch)["status"] == "pending"
    for user, status in ((INACTIVE, "suspended"), (REVOKED, "revoked")):
        assert (
            query(
                owner,
                "SELECT status FROM organization_memberships WHERE organization_id=:org AND user_id=:user",
                org=ORG,
                user=user,
            )
            == status
        )
    denied(lambda: imports.command(ORG, claimant, "claim", batch))
    second = imports.upload(
        ORG, staff, b"email\nsecond@example.invalid\n", "csv", "email"
    )
    with ThreadPoolExecutor(max_workers=1) as pool:
        with owner.begin() as conn:
            conn.execute(
                text("DELETE FROM membership_roles WHERE membership_id=:id"),
                {"id": STAFF},
            )
            confirmation = pool.submit(
                imports.command,
                ORG,
                staff,
                "confirm",
                UUID(str(second["batch_id"])),
                bytes.fromhex(str(second["version"])),
            )
        denied(confirmation.result)
    for engine in (api, role("veriq_worker")):
        try:
            query(engine, "SELECT count(*) FROM user_import_rows")
        except DBAPIError as error:
            assert error.orig.sqlstate == "42501"
        else:
            raise AssertionError("Runtime can read raw staged rows")
    query(owner, "UPDATE user_import_batches SET expires_at=now()-interval '1 second'")
    assert query(role("veriq_worker"), "SELECT public.veriq_import_purge()") == 2
    assert query(owner, "SELECT count(*) FROM user_import_rows") == 0
    print(
        "Bulk import: upgrade, idempotence, concurrent confirm/revocation, claims, RLS and cleanup passed."
    )


if __name__ == "__main__":
    owner_engine = create_database_engine()
    if sys.argv[1:] == ["seed"]:
        seed(owner_engine)
    else:
        run(owner_engine, role("veriq_api"))
