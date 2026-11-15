"""Verify 0025 against a fresh disposable database in each mode."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from time import monotonic, sleep
from uuid import uuid4

from academic_catalog_checks import ADMIN, ORG, OUTSIDER, role
from academic_group_teacher_schema_checks import expect_state, fixture, snapshot
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError
from veriq.academic_catalog import AcademicCatalog, CatalogInput, CatalogKind
from veriq.auth_credentials import CredentialVerifier
from veriq.database import create_database_engine
from veriq.sessions import Sessions

TABLE = "public.group_memberships"
INSERT = f"""
    INSERT INTO {TABLE} (organization_id,id,group_id,membership_id,start_at,end_at)
    VALUES (:org,:id,:group_id,:member,:start,:end)
"""


def concurrent_insert(owner: Engine, row: dict[str, object]) -> None:
    backend: Queue[int] = Queue()

    def contender() -> str | None:
        try:
            with owner.begin() as db:
                db.exec_driver_sql("SET LOCAL statement_timeout = '15s'")
                backend.put(db.exec_driver_sql("SELECT pg_backend_pid()").scalar_one())
                db.execute(text(INSERT), row | {"id": uuid4()})
        except DBAPIError as exc:
            return getattr(exc.orig, "sqlstate", None)
        return None

    with ThreadPoolExecutor(1) as pool:
        with owner.begin() as db:
            db.execute(text(INSERT), row)
            future = pool.submit(contender)
            contender_pid = backend.get(timeout=5)
            first_pid = db.exec_driver_sql("SELECT pg_backend_pid()").scalar_one()
            with owner.connect() as observer:
                deadline = monotonic() + 5
                while not observer.scalar(
                    text("SELECT :first = ANY(pg_blocking_pids(:second))"),
                    {"first": first_pid, "second": contender_pid},
                ):
                    assert not future.done(), "Contender completed without waiting"
                    assert monotonic() < deadline, (
                        "Contender did not wait for first INSERT"
                    )
                    sleep(0.02)
        assert future.result(timeout=16) == "23P01"

    with owner.connect() as db:
        assert db.execute(
            text(f"""SELECT id FROM {TABLE}
                WHERE organization_id=:org AND group_id=:group_id AND membership_id=:member
                AND tstzrange(start_at,end_at,'[)') && tstzrange(:start,:end,'[)')"""),
            row,
        ).scalars().all() == [row["id"]]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("clean", "upgrade"))
    mode = parser.parse_args().mode
    owner = create_database_engine()
    with owner.connect() as db:
        assert db.scalar(text("SELECT to_regclass('public.alembic_version')")) is None
    config = Config("alembic.ini")
    command.upgrade(config, "0024" if mode == "upgrade" else "0025")
    a, b = fixture(owner)
    second_group = uuid4()
    sessions = Sessions(role("veriq_api"), issuer=role("veriq_session_issuer"))
    actor = sessions.issue(
        CredentialVerifier(role("veriq_credential_verifier")).confirm(
            ADMIN, 1, mfa_level=1, organization_id=ORG
        )
    )
    AcademicCatalog(sessions).write(
        actor,
        ORG,
        CatalogKind.GROUPS,
        second_group,
        CatalogInput(title="Second group"),
        uuid4(),
    )
    if mode == "upgrade":
        with owner.begin() as db:
            db.execute(
                text("""
                INSERT INTO academic_group_teacher_assignments
                    (organization_id,id,group_id,membership_id,grant_epoch,granted_at,revoked_at)
                SELECT :org,:id,:group_id,id,grant_epoch,now(),now()
                FROM organization_memberships WHERE id=:member
            """),
                {"org": ORG, "id": uuid4(), "group_id": a, "member": ADMIN},
            )
            before = snapshot(db)
            history = db.exec_driver_sql(
                "SELECT to_jsonb(t) FROM academic_group_teacher_assignments t"
            ).scalar_one()
        command.upgrade(config, "0025")
        with owner.connect() as db:
            assert snapshot(db) == before
            assert (
                db.exec_driver_sql(
                    "SELECT to_jsonb(t) FROM academic_group_teacher_assignments t"
                ).scalar_one()
                == history
            )

    row = {
        "org": ORG,
        "id": uuid4(),
        "group_id": a,
        "member": ADMIN,
        "start": "2026-01-01T00:00:00Z",
        "end": None,
    }
    boundary = "2026-02-01T00:00:00Z"
    with owner.begin() as db:
        assert db.scalar(text("SELECT version_num FROM alembic_version")) == "0025"
        assert db.execute(
            text("""
            SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid=to_regclass(:name)
        """),
            {"name": TABLE},
        ).one() == (True, True)
        expect_state(db, INSERT, "23503", **(row | {"group_id": b}))
        expect_state(db, INSERT, "23503", **(row | {"member": OUTSIDER}))
        expect_state(db, INSERT, "23514", **(row | {"end": row["start"]}))
        db.execute(text(INSERT), row)
        expect_state(db, INSERT, "23P01", **(row | {"id": uuid4(), "start": boundary}))
        db.execute(text(INSERT), row | {"id": uuid4(), "group_id": second_group})
        db.execute(
            text(f"UPDATE {TABLE} SET end_at=:end WHERE id=:id"),
            {"end": boundary, "id": row["id"]},
        )
        assert db.scalar(
            text(f"SELECT end_at IS NOT NULL FROM {TABLE} WHERE id=:id"), row
        )
    concurrent_insert(owner, row | {"id": uuid4(), "start": boundary})

    with role("veriq_api").begin() as db:
        assert db.scalar(text("SELECT current_user")) == "veriq_api"
        expect_state(db, f"SELECT * FROM {TABLE}", "42501")
        expect_state(db, INSERT, "42501", **row)
        expect_state(db, f"UPDATE {TABLE} SET end_at=now()", "42501")
        expect_state(db, f"DELETE FROM {TABLE}", "42501")
    print(
        f"0025 {mode}: preservation, interval history, concurrency, tenant FKs and runtime denials passed"
    )


if __name__ == "__main__":
    main()
