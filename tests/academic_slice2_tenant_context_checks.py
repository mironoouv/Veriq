"""Check function-local tenant context on a disposable PostgreSQL 17.11."""

from uuid import uuid4

from academic_catalog_checks import ADMIN, ORG, OTHER, OUTSIDER, role
from academic_group_teacher_schema_checks import expect_state, fixture
from sqlalchemy import text
from veriq.database import create_database_engine

ROLE = "veriq_test_context"
GUC = "SELECT current_setting('veriq.organization_id', true)"
SET_CONTEXT = text("SELECT set_config('veriq.organization_id', :tenant, true)")
CALL = "SELECT * FROM public.veriq_test_scoped_context(:tenant, :fail)"


def main() -> None:
    owner = create_database_engine()
    reader = role(ROLE)
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
            for org, member, group in zip(
                (ORG, OTHER), (ADMIN, OUTSIDER), groups, strict=True
            ):
                db.execute(
                    text("""
                    INSERT INTO public.group_memberships (organization_id,id,group_id,membership_id)
                    VALUES (:org,:id,:group,:member)
                """),
                    {"org": org, "id": uuid4(), "group": group, "member": member},
                )
            db.exec_driver_sql(f"CREATE ROLE {ROLE} NOLOGIN NOBYPASSRLS NOSUPERUSER")
            db.exec_driver_sql(f"GRANT USAGE ON SCHEMA public TO {ROLE}")
            for table in ("group_memberships", "organization_memberships"):
                db.exec_driver_sql(
                    f"GRANT SELECT (organization_id) ON public.{table} TO {ROLE}"
                )
                db.exec_driver_sql(f"""
                    CREATE POLICY test_context ON public.{table} FOR SELECT TO {ROLE}
                    USING (organization_id::text =
                           nullif(current_setting('veriq.organization_id', true), ''))
                """)
            db.exec_driver_sql(f"""
                CREATE FUNCTION public.veriq_test_scoped_context(tenant text, fail boolean)
                RETURNS TABLE (entry_context text, inside_context text)
                LANGUAGE plpgsql SECURITY INVOKER
                SET search_path TO pg_catalog, pg_temp
                SET veriq.organization_id TO ''
                AS $body$
                BEGIN
                    entry_context := current_setting('veriq.organization_id', true);
                    IF entry_context IS DISTINCT FROM '' THEN
                        RAISE EXCEPTION 'Entry context was not cleared';
                    END IF;
                    IF EXISTS (SELECT organization_id FROM public.group_memberships)
                       OR EXISTS (SELECT organization_id FROM public.organization_memberships) THEN
                        RAISE EXCEPTION 'Rows visible before setting tenant';
                    END IF;
                    inside_context := set_config('veriq.organization_id', tenant, true);
                    IF (SELECT array_agg(organization_id::text) FROM public.group_memberships)
                           IS DISTINCT FROM ARRAY[tenant]
                       OR (SELECT array_agg(organization_id::text)
                           FROM public.organization_memberships)
                           IS DISTINCT FROM ARRAY[tenant] THEN
                        RAISE EXCEPTION 'Unexpected rows under tenant context';
                    END IF;
                    IF fail THEN
                        RAISE EXCEPTION 'Controlled test exception' USING ERRCODE = 'P7501';
                    END IF;
                    RETURN NEXT;
                END;
                $body$;
                REVOKE ALL ON FUNCTION public.veriq_test_scoped_context(text, boolean) FROM PUBLIC;
                GRANT EXECUTE ON FUNCTION public.veriq_test_scoped_context(text, boolean) TO {ROLE};
            """)

        with reader.begin() as db:
            db.exec_driver_sql("SET LOCAL statement_timeout = '5s'")
            assert db.exec_driver_sql("SELECT current_user").scalar_one() == ROLE
            assert (
                db.exec_driver_sql("""
                SELECT count(*) FROM pg_class
                WHERE oid IN ('public.group_memberships'::regclass,
                              'public.organization_memberships'::regclass)
                  AND relrowsecurity AND relforcerowsecurity
                  AND NOT pg_has_role(relowner,'USAGE')
            """).scalar_one()
                == 2
            )
            for original in (str(OTHER), ""):
                db.execute(SET_CONTEXT, {"tenant": original})
                assert db.exec_driver_sql(GUC).scalar_one() == original
                assert db.execute(
                    text(CALL), {"tenant": str(ORG), "fail": False}
                ).one() == ("", str(ORG))
                assert db.exec_driver_sql(GUC).scalar_one() == original
                expect_state(db, CALL, "P7501", tenant=str(ORG), fail=True)
                assert db.exec_driver_sql(GUC).scalar_one() == original
        print(
            "Functional SET and FORCE RLS passed, caller context restored after return and error"
        )
    finally:
        reader.dispose()
        owner.dispose()


if __name__ == "__main__":
    main()
