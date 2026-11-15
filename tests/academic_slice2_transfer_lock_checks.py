"""Test transfer lock interactions on a disposable migrated PostgreSQL database."""

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from time import monotonic, sleep
from uuid import UUID, uuid4

from academic_catalog_checks import ADMIN, ORG, role
from academic_group_teacher_schema_checks import expect_state, fixture
from sqlalchemy import Connection, Engine
from veriq.auth_credentials import CredentialVerifier
from veriq.database import create_database_engine
from veriq.sessions import SessionPolicy, Sessions

Action = Callable[[Connection], object]


def verify_orders(
    owner: Engine,
    writer: Engine,
    lock: Action,
    revoke: Action,
    revoked: Action,
    *,
    writer_try: Action | None = None,
) -> None:
    pids: Queue[int] = Queue()

    def write() -> None:
        with writer.begin() as db:
            db.exec_driver_sql("SET LOCAL statement_timeout='15s'")
            pids.put(db.exec_driver_sql("SELECT pg_backend_pid()").scalar_one())
            assert revoke(db)

    with ThreadPoolExecutor(1) as pool:
        with owner.begin() as first:
            assert lock(first)
            assert not revoked(first)
            if writer_try is not None:
                with writer.begin() as db:
                    assert writer_try(db) is False
            future = pool.submit(write)
            second_pid = pids.get(timeout=5)
            first_pid = first.exec_driver_sql("SELECT pg_backend_pid()").scalar_one()
            with owner.connect() as observer:
                deadline = monotonic() + 5
                while not observer.exec_driver_sql(
                    "SELECT %s = ANY(pg_blocking_pids(%s))", (first_pid, second_pid)
                ).scalar_one():
                    assert not future.done()
                    assert monotonic() < deadline, (
                        "Writer did not wait for transfer lock"
                    )
                    sleep(0.02)
        future.result(timeout=16)
    with owner.begin() as db:
        assert lock(db)
        assert revoked(db), "Committed revocation must be visible after locking"


def row_scenario(
    owner: Engine,
    writer: Engine,
    table: str,
    key: object,
    revoke: Action,
    revoked: Action,
) -> None:
    from sqlalchemy import text

    statement = f"SELECT id FROM public.{table} WHERE id=:id FOR NO KEY UPDATE NOWAIT"

    def lock(db: Connection) -> object:
        return db.scalar(text(statement), {"id": key})

    # Roll back this first writer so the waiting-writer case starts from active state.
    with writer.connect() as db, db.begin() as tx:
        assert revoke(db)
        with owner.begin() as contender:
            expect_state(contender, statement, "55P03", id=key)
        tx.rollback()
    verify_orders(owner, writer, lock, revoke, revoked)


def main() -> None:
    owner = create_database_engine()
    api = role("veriq_api")
    issuer = role("veriq_session_issuer")
    verifier = role("veriq_credential_verifier")
    with owner.connect() as db:
        assert db.exec_driver_sql("SHOW server_version_num").scalar_one() == "170011"
        assert (
            db.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one()
            == "0025"
        )
        assert not db.exec_driver_sql(
            "SELECT EXISTS (SELECT FROM organizations)"
        ).scalar_one()
    groups = fixture(owner)
    gate = (
        Sessions(api, issuer=issuer)
        .issue(
            CredentialVerifier(verifier).confirm(
                ADMIN, 1, mfa_level=1, organization_id=ORG
            )
        )
        ._gate(SessionPolicy())
    )

    row_scenario(
        owner,
        api,
        "auth_sessions",
        gate.session_id,
        lambda db: (
            db.exec_driver_sql(
                "SELECT public.veriq_auth_revoke(%s,%s,%s::interval[],false,%s,%s,%s)",
                (
                    gate.session_id,
                    gate.digest,
                    list(gate.limits),
                    uuid4(),
                    uuid4(),
                    uuid4(),
                ),
            ).scalar_one()
            == 1
        ),
        lambda db: db.exec_driver_sql(
            "SELECT revoked_at IS NOT NULL FROM auth_sessions WHERE id=%s",
            (gate.session_id,),
        ).scalar_one(),
    )
    student = uuid4()
    with owner.begin() as db:
        db.exec_driver_sql(
            "INSERT INTO users(id,email_normalized,password_hash) VALUES (%s,%s,'fixture')",
            (student, f"{student.hex}@example.invalid"),
        )
        db.exec_driver_sql(
            """INSERT INTO organization_memberships(id,organization_id,user_id,status)
               VALUES (%s,%s,%s,'active')""",
            (student, ORG, student),
        )
    for account in (ADMIN, student):
        row_scenario(
            owner,
            owner,
            "users",
            account,
            lambda db, account=account: (
                db.exec_driver_sql(
                    "UPDATE users SET disabled_at=clock_timestamp() WHERE id=%s",
                    (account,),
                ).rowcount
                == 1
            ),
            lambda db, account=account: db.exec_driver_sql(
                "SELECT disabled_at IS NOT NULL FROM users WHERE id=%s", (account,)
            ).scalar_one(),
        )

    # Provision a second group in A through the catalog before changing assignments.
    from veriq.academic_catalog import AcademicCatalog, CatalogInput, CatalogKind

    with owner.begin() as db:
        db.exec_driver_sql("UPDATE users SET disabled_at=NULL WHERE id=%s", (ADMIN,))
    sessions = Sessions(api, issuer=issuer)
    actor = sessions.issue(
        CredentialVerifier(verifier).confirm(ADMIN, 1, mfa_level=1, organization_id=ORG)
    )
    second = uuid4()
    AcademicCatalog(sessions).write(
        actor,
        ORG,
        CatalogKind.GROUPS,
        second,
        CatalogInput(title="Destination fixture"),
        uuid4(),
    )

    for group in (groups[0], second):
        assignment = uuid4()
        with owner.begin() as db:
            db.exec_driver_sql(
                """INSERT INTO academic_group_teacher_assignments
                   (organization_id,id,group_id,membership_id,grant_epoch)
                   SELECT %s,%s,%s,id,grant_epoch FROM organization_memberships
                   WHERE organization_id=%s AND id=%s""",
                (ORG, assignment, group, ORG, ADMIN),
            )

        def revoke_assignment(db: Connection, assignment_id: UUID = assignment) -> bool:
            db.exec_driver_sql("SELECT pg_advisory_xact_lock(670013::bigint)")
            return (
                db.exec_driver_sql(
                    """UPDATE academic_group_teacher_assignments SET revoked_at=clock_timestamp()
                   WHERE organization_id=%s AND id=%s AND revoked_at IS NULL""",
                    (ORG, assignment_id),
                ).rowcount
                == 1
            )

        def shared(db: Connection) -> object:
            return db.exec_driver_sql(
                "SELECT pg_try_advisory_xact_lock_shared(670013::bigint)"
            ).scalar_one()

        with owner.connect() as db, db.begin() as tx:
            assert revoke_assignment(db)
            with owner.begin() as contender:
                assert shared(contender) is False
            tx.rollback()
        verify_orders(
            owner,
            owner,
            shared,
            revoke_assignment,
            lambda db, assignment_id=assignment: db.exec_driver_sql(
                """SELECT revoked_at IS NOT NULL FROM academic_group_teacher_assignments
                   WHERE organization_id=%s AND id=%s""",
                (ORG, assignment_id),
            ).scalar_one(),
            writer_try=lambda db: db.exec_driver_sql(
                "SELECT pg_try_advisory_xact_lock(670013::bigint)"
            ).scalar_one(),
        )
    print("Transfer locks: logout, both account rows and both group assignments passed")


if __name__ == "__main__":
    main()
