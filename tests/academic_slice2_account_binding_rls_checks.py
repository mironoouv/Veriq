"""Verify proposed account binding reads on a disposable migrated PostgreSQL."""

from uuid import uuid4

from academic_catalog_checks import ADMIN, ORG, OTHER, OUTSIDER, role
from academic_group_teacher_schema_checks import fixture
from sqlalchemy import text
from veriq.database import create_database_engine

ROLE = "veriq_test_account_binding"
COLUMNS = {
    "group_memberships": ("organization_id", "id", "membership_id", "end_at"),
    "organization_memberships": ("organization_id", "id", "user_id", "status"),
}
LOOKUP = text("""
    SELECT member.user_id
    FROM public.group_memberships AS interval
    JOIN public.organization_memberships AS member
      ON member.organization_id=interval.organization_id
     AND member.id=interval.membership_id
    WHERE interval.organization_id::text=current_setting('veriq.organization_id', true)
      AND interval.id=:id AND interval.end_at IS NULL AND member.status='active'
""")
CONTEXT = text("SELECT set_config('veriq.organization_id', :tenant, true)")


def main() -> None:
    owner = create_database_engine()
    reader = role(ROLE)
    source, foreign, closed, replacement = (uuid4() for _ in range(4))
    try:
        with owner.connect() as db:
            assert (
                db.exec_driver_sql("SHOW server_version_num").scalar_one() == "170011"
            )
            assert not db.exec_driver_sql(
                "SELECT EXISTS (SELECT FROM organizations)"
            ).scalar_one()
        group_a, group_b = fixture(owner)
        with owner.begin() as db:
            db.execute(
                text("""
                INSERT INTO public.organization_memberships(id,organization_id,user_id,status)
                VALUES (:id,:org,:account,'active')
            """),
                {"id": replacement, "org": ORG, "account": OUTSIDER},
            )
            for interval_id, org, group, member, end in (
                (source, ORG, group_a, ADMIN, None),
                (foreign, OTHER, group_b, OUTSIDER, None),
                (closed, ORG, group_a, ADMIN, "2000-01-02"),
            ):
                db.execute(
                    text("""
                    INSERT INTO public.group_memberships
                        (id,organization_id,group_id,membership_id,start_at,end_at)
                    VALUES (:id,:org,:group,:member,
                            CASE WHEN CAST(:end AS timestamptz) IS NULL THEN now()
                                 ELSE TIMESTAMPTZ '2000-01-01' END, CAST(:end AS timestamptz))
                """),
                    {
                        "id": interval_id,
                        "org": org,
                        "group": group,
                        "member": member,
                        "end": end,
                    },
                )
            db.exec_driver_sql(f"CREATE ROLE {ROLE} NOLOGIN NOBYPASSRLS NOSUPERUSER")
            db.exec_driver_sql(f"GRANT USAGE ON SCHEMA public TO {ROLE}")
            for table, columns in COLUMNS.items():
                db.exec_driver_sql(
                    f"GRANT SELECT ({', '.join(columns)}) ON public.{table} TO {ROLE}"
                )
                db.exec_driver_sql(f"""
                    CREATE POLICY test_account_binding ON public.{table} FOR SELECT TO {ROLE}
                    USING (organization_id::text =
                           nullif(current_setting('veriq.organization_id', true), ''))
                """)

        with reader.begin() as db:
            assert db.exec_driver_sql("""
                SELECT current_user, rolcanlogin, rolbypassrls, rolsuper
                FROM pg_roles WHERE rolname=current_user
            """).one() == (ROLE, False, False, False)
            assert (
                db.exec_driver_sql(
                    "SELECT current_setting('veriq.organization_id', true)"
                ).scalar_one()
                is None
            )
            for table, columns in COLUMNS.items():
                assert db.execute(
                    text("""
                    SELECT relrowsecurity, relforcerowsecurity, pg_has_role(relowner,'USAGE'),
                           has_table_privilege(oid,'SELECT,INSERT,UPDATE,DELETE')
                    FROM pg_class WHERE oid=CAST(:table AS regclass)
                """),
                    {"table": f"public.{table}"},
                ).one() == (True, True, False, False)
                grants = db.execute(
                    text("""
                    SELECT attname, has_column_privilege(attrelid,attnum,'SELECT'),
                           has_column_privilege(attrelid,attnum,'INSERT,UPDATE,REFERENCES')
                    FROM pg_attribute
                    WHERE attrelid=CAST(:table AS regclass) AND attnum>0 AND NOT attisdropped
                """),
                    {"table": f"public.{table}"},
                ).all()
                assert {name for name, select, _ in grants if select} == set(columns)
                assert not any(write for _, _, write in grants)
                assert db.exec_driver_sql(f"SELECT id FROM public.{table}").all() == []
            db.execute(CONTEXT, {"tenant": ""})
            for table in COLUMNS:
                assert db.exec_driver_sql(f"SELECT id FROM public.{table}").all() == []
            db.execute(CONTEXT, {"tenant": str(OTHER)})
            for table in COLUMNS:
                assert set(
                    db.exec_driver_sql(
                        f"SELECT organization_id FROM public.{table}"
                    ).scalars()
                ) == {OTHER}
            assert db.scalar(LOOKUP, {"id": foreign}) == OUTSIDER
            db.execute(CONTEXT, {"tenant": str(ORG)})
            for table in COLUMNS:
                assert set(
                    db.exec_driver_sql(
                        f"SELECT organization_id FROM public.{table}"
                    ).scalars()
                ) == {ORG}
            assert db.scalar(LOOKUP, {"id": foreign}) is None
            assert db.scalar(LOOKUP, {"id": closed}) is None
            expected = db.scalar(LOOKUP, {"id": source})
            assert expected == ADMIN
            with owner.begin() as writer:
                writer.exec_driver_sql("SET LOCAL statement_timeout = '5s'")
                assert writer.exec_driver_sql(
                    "SELECT pg_backend_pid()"
                ).scalar_one() != (
                    db.exec_driver_sql("SELECT pg_backend_pid()").scalar_one()
                )
                writer.execute(
                    text("""
                    UPDATE public.group_memberships SET membership_id=:member
                    WHERE organization_id=:org AND id=:id
                """),
                    {"org": ORG, "id": source, "member": replacement},
                )
            current = db.scalar(LOOKUP, {"id": source})
            assert current == OUTSIDER and current != expected
            with owner.begin() as writer:
                writer.exec_driver_sql("SET LOCAL statement_timeout = '5s'")
                writer.execute(
                    text("""
                    UPDATE public.organization_memberships SET status='suspended'
                    WHERE organization_id=:org AND id=:member
                """),
                    {"org": ORG, "member": replacement},
                )
            assert db.scalar(LOOKUP, {"id": source}) is None
        print("FORCE RLS, column ACL, tenant A/B and account binding recheck passed")
    finally:
        reader.dispose()
        owner.dispose()


if __name__ == "__main__":
    main()
