"""Check account lock privileges on a migrated, disposable PostgreSQL 17.11."""

from uuid import uuid4

from academic_catalog_checks import ADMIN, ORG, OTHER, OUTSIDER, role
from academic_group_teacher_schema_checks import expect_state, fixture
from sqlalchemy import Connection, text
from veriq.database import create_database_engine

READ = (
    "SELECT id, disabled_at FROM public.users WHERE id IN (:first, :second) ORDER BY id"
)
ACCOUNTS = {"first": ADMIN, "second": OUTSIDER}
LOCK = READ + " FOR NO KEY UPDATE NOWAIT"


def snapshot(db: Connection) -> tuple[tuple, tuple]:
    return (
        tuple(db.execute(text(READ), ACCOUNTS).tuples()),
        tuple(
            db.exec_driver_sql("""
            SELECT to_jsonb(m) FROM public.group_memberships AS m ORDER BY organization_id,id
        """).scalars()
        ),
    )


def main() -> None:
    owner = create_database_engine()
    store = role("veriq_session_store")
    try:
        with owner.connect() as db:
            assert (
                db.exec_driver_sql("SHOW server_version_num").scalar_one() == "170011"
            )
            assert not db.exec_driver_sql(
                "SELECT EXISTS (SELECT FROM organizations)"
            ).scalar_one()
        groups = fixture(owner)
        with owner.begin() as db:
            db.execute(
                text("""
                UPDATE public.users SET disabled_at=clock_timestamp() WHERE id=:id
            """),
                {"id": OUTSIDER},
            )
            for org, account, group in zip(
                (ORG, OTHER), (ADMIN, OUTSIDER), groups, strict=True
            ):
                db.execute(
                    text("""
                    INSERT INTO public.group_memberships
                        (organization_id,id,group_id,membership_id,start_at)
                    VALUES (:org,:id,:group,:account,clock_timestamp())
                """),
                    {"org": org, "id": uuid4(), "group": group, "account": account},
                )
        with owner.connect() as db:
            before = snapshot(db)
        assert len(before[1]) == 2
        assert before[0][0] == (ADMIN, None)
        assert before[0][1][0] == OUTSIDER and before[0][1][1] is not None

        with store.begin() as db:
            db.exec_driver_sql("SET LOCAL statement_timeout = '5s'")
            assert (
                db.exec_driver_sql("SELECT current_user").scalar_one()
                == "veriq_session_store"
            )
            privileges = db.exec_driver_sql("""
                SELECT attname,
                       has_column_privilege(attrelid,attnum,'SELECT'),
                       has_column_privilege(attrelid,attnum,'UPDATE')
                FROM pg_attribute
                WHERE attrelid='public.users'::regclass AND attnum > 0 AND NOT attisdropped
                AND (has_column_privilege(attrelid,attnum,'SELECT')
                     OR has_column_privilege(attrelid,attnum,'UPDATE'))
                ORDER BY attname
            """).all()
            assert ("disabled_at", True, False) in privileges
            assert ("id", True, False) in privileges
            assert {name for name, _, update in privileges if update} == {
                "credential_version",
                "password_hash",
                "updated_at",
            }
            assert tuple(db.execute(text(READ), ACCOUNTS).tuples()) == before[0]
            assert tuple(db.execute(text(LOCK), ACCOUNTS).tuples()) == before[0]
            with store.begin() as contender:
                contender.exec_driver_sql("SET LOCAL statement_timeout = '5s'")
                assert contender.exec_driver_sql(
                    "SELECT pg_backend_pid()"
                ).scalar_one() != (
                    db.exec_driver_sql("SELECT pg_backend_pid()").scalar_one()
                )
                expect_state(contender, LOCK, "55P03", **ACCOUNTS)

        with owner.connect() as db:
            assert snapshot(db) == before
        print(
            "Account status SELECT and row lock passed, NOWAIT returned 55P03, snapshots unchanged"
        )
    finally:
        store.dispose()
        owner.dispose()


if __name__ == "__main__":
    main()
