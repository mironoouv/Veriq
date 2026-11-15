"""Check Slice 2 ACLs on a freshly migrated synthetic Compose database."""

import os
from uuid import uuid4

from academic_catalog_checks import ADMIN, ORG, OTHER, OUTSIDER
from academic_group_teacher_schema_checks import expect_state, fixture
from sqlalchemy import Connection, text
from veriq.database import create_database_engine, database_url

TABLES = {
    "group_memberships": ("start_at", "clock_timestamp()"),
    "academic_group_teacher_assignments": ("grant_epoch", "0"),
}


def snapshot(db: Connection, table: str) -> list[object]:
    return list(
        db.exec_driver_sql(
            f"SELECT to_jsonb(t) FROM public.{table} t ORDER BY organization_id,id"
        ).scalars()
    )


def assert_closed(db: Connection, table: str) -> None:
    flags = db.execute(
        text("""
            SELECT c.relrowsecurity, c.relforcerowsecurity,
                   pg_has_role(c.relowner, 'MEMBER'), r.rolbypassrls, r.rolsuper
            FROM pg_class c JOIN pg_roles r ON r.rolname=current_user
            WHERE c.oid=to_regclass(:table)
        """),
        {"table": f"public.{table}"},
    ).one()
    assert flags == (True, True, False, False, False), (table, flags)
    assert not db.scalar(
        text("""
            SELECT EXISTS (
                SELECT FROM unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE',
                    'TRUNCATE','REFERENCES','TRIGGER','MAINTAIN']) AS p(privilege)
                WHERE has_table_privilege(current_user, :table, p.privilege)
            ) OR EXISTS (
                SELECT FROM pg_attribute AS a
                CROSS JOIN unnest(ARRAY['SELECT','INSERT','UPDATE','REFERENCES']) AS p(privilege)
                WHERE a.attrelid=to_regclass(:table) AND a.attnum>0 AND NOT a.attisdropped
                AND has_column_privilege(current_user, a.attrelid, a.attnum, p.privilege)
            )
        """),
        {"table": f"public.{table}"},
    ), table


def main() -> None:
    owner = create_database_engine()
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
    with owner.begin() as db:
        for table, (column, value) in TABLES.items():
            for org, member, group in zip(
                (ORG, OTHER), (ADMIN, OUTSIDER), groups, strict=True
            ):
                db.execute(
                    text(f"""INSERT INTO public.{table}
                        (organization_id,id,group_id,membership_id,{column})
                        VALUES (:org,:id,:group_id,:member,{value})"""),
                    {"org": org, "id": uuid4(), "group_id": group, "member": member},
                )
        before = {table: snapshot(db, table) for table in TABLES}
        assert all(len(rows) == 2 for rows in before.values())

    for role, secret in (
        ("veriq_api", "VERIQ_API_DB_PASSWORD"),
        ("veriq_worker", "VERIQ_WORKER_DB_PASSWORD"),
    ):
        runtime = create_database_engine(
            database_url().set(username=role, password=os.environ[secret])
        )
        try:
            with runtime.begin() as db:
                assert tuple(
                    db.exec_driver_sql("SELECT current_user, session_user").one()
                ) == (role, role)
                for table, (column, value) in TABLES.items():
                    assert_closed(db, table)
                    expect_state(db, f"SELECT id FROM public.{table}", "42501")
                    expect_state(
                        db,
                        f"""INSERT INTO public.{table}
                            (organization_id,id,group_id,membership_id,{column})
                            VALUES (:org,:id,:group_id,:member,{value})""",
                        "42501",
                        org=ORG,
                        id=uuid4(),
                        group_id=groups[0],
                        member=ADMIN,
                    )
                    expect_state(
                        db, f"UPDATE public.{table} SET {column}={value}", "42501"
                    )
                    expect_state(db, f"DELETE FROM public.{table}", "42501")
        finally:
            runtime.dispose()
        print(f"{role}: ownership, RLS, effective ACL and SQLSTATE 42501 checks passed")

    with owner.connect() as db:
        assert {table: snapshot(db, table) for table in TABLES} == before
    owner.dispose()
    print("Synthetic tenant A/B rows unchanged")


if __name__ == "__main__":
    main()
