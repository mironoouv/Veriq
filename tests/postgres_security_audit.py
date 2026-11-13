"""Read effective privileges and exercise denied operations on synthetic databases."""

import os
import sys

from psycopg import connect, errors

PUBLIC_EXECUTE = (
    "EXISTS (SELECT FROM aclexplode(coalesce(p.proacl, acldefault('f',p.proowner))) a "
    "WHERE a.grantee=0 AND a.privilege_type='EXECUTE')"
)


def connection(database: str, role: str, password: str):
    return connect(
        host=os.environ["VERIQ_DB_HOST"],
        dbname=database,
        user=role,
        password=password,
        autocommit=True,
    )


def inventory(database: str):
    with connection(database, "veriq_dev", os.environ["VERIQ_DB_PASSWORD"]) as db:
        assert db.execute("SHOW server_version_num").fetchone() == ("170011",)
        with db.transaction(force_rollback=True):
            db.execute(
                "CREATE FUNCTION public.audit_acl_fixture() RETURNS integer LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'"
            )
            probe = f"SELECT {PUBLIC_EXECUTE} FROM pg_proc p WHERE p.oid='public.audit_acl_fixture()'::regprocedure"
            assert db.execute(probe).fetchone() == (True,)
            db.execute(
                "REVOKE EXECUTE ON FUNCTION public.audit_acl_fixture() FROM PUBLIC"
            )
            assert db.execute(probe).fetchone() == (False,)
            db.execute("GRANT EXECUTE ON FUNCTION public.audit_acl_fixture() TO PUBLIC")
            assert db.execute(probe).fetchone() == (True,)
        routines = db.execute(f"""
            SELECT p.oid::regprocedure::text, p.proowner::regrole::text,
                   p.proconfig, {PUBLIC_EXECUTE},
                   ARRAY(SELECT rolname FROM pg_roles
                         WHERE rolname LIKE 'veriq_%'
                           AND has_function_privilege(pg_roles.oid,p.oid,'EXECUTE')
                         ORDER BY rolname)
            FROM pg_proc p WHERE pronamespace='public'::regnamespace AND prosecdef
            ORDER BY 1
        """).fetchall()
        assert routines
        for signature, owner, config, public_execute, callers in routines:
            assert not public_execute, signature
            assert owner not in {"veriq_api", "veriq_worker", "veriq_dev"}, signature
            assert "search_path=pg_catalog, pg_temp" in (config or []), signature
            print(signature, owner, ",".join(callers))
        relations = db.execute("""
            SELECT relname,relowner::regrole::text,relrowsecurity,relforcerowsecurity,
                   relacl::text
            FROM pg_class WHERE relnamespace='public'::regnamespace ORDER BY 1
        """).fetchall()
        columns = db.execute("""
            SELECT c.relname,a.attname,a.attacl::text FROM pg_attribute a
            JOIN pg_class c ON c.oid=a.attrelid
            WHERE c.relnamespace='public'::regnamespace AND a.attacl IS NOT NULL
            ORDER BY 1,2
        """).fetchall()
        return routines, relations, columns


def denied(db, statement: str) -> None:
    try:
        db.execute(statement)
    except errors.InsufficientPrivilege:
        print("Denied (42501):", statement)
    else:
        raise AssertionError(f"Expected permission denial: {statement}")


def main() -> None:
    clean, upgraded = sys.argv[1:]
    assert inventory(clean) == inventory(upgraded)
    print("PostgreSQL 17.11: clean and upgraded ACL snapshots match")
    with connection(upgraded, "veriq_dev", os.environ["VERIQ_DB_PASSWORD"]) as owner:
        before = owner.execute(
            "SELECT count(*) FROM academic_catalog_events"
        ).fetchone()
        org, subject, item = owner.execute("""
            SELECT c.organization_id,m.user_id,c.id
            FROM courses c JOIN organization_memberships m USING (organization_id)
            JOIN membership_roles r ON r.organization_id=m.organization_id AND r.membership_id=m.id
            JOIN organization_role_permissions p ON p.organization_id=r.organization_id AND p.role_id=r.role_id
            WHERE c.status='active' AND m.status='active'
              AND p.permission_code='academic.catalog.manage' LIMIT 1
        """).fetchone()
        with connection(
            upgraded, "veriq_api", os.environ["VERIQ_API_DB_PASSWORD"]
        ) as api:
            with api.transaction(force_rollback=True):
                api.execute(
                    "SELECT set_config('veriq.organization_id',%s,true),set_config('veriq.user_id',%s,true)",
                    (str(org), str(subject)),
                )
                denied(
                    api,
                    f"UPDATE courses SET title='Audit SQL fixture' WHERE organization_id='{org}' AND id='{item}'",
                )
            assert (
                owner.execute("SELECT count(*) FROM academic_catalog_events").fetchone()
                == before
            )
            denied(api, "INSERT INTO academic_catalog_events DEFAULT VALUES")

    for database in (clean, upgraded):
        for role, variable in (
            ("veriq_api", "VERIQ_API_DB_PASSWORD"),
            ("veriq_worker", "VERIQ_WORKER_DB_PASSWORD"),
        ):
            with connection(database, role, os.environ[variable]) as db:
                assert db.execute("SELECT session_user,current_user").fetchone() == (
                    role,
                    role,
                )
                assert db.execute("""
                    SELECT rolsuper,rolbypassrls,rolcreaterole FROM pg_roles
                    WHERE rolname=current_user
                """).fetchone() == (False, False, False)
                denied(db, "SELECT * FROM auth_sessions")
                denied(db, "DELETE FROM academic_catalog_events WHERE false")
                if role == "veriq_api":
                    denied(db, "SELECT public.veriq_import_purge()")
                    assert db.execute("SELECT count(*) FROM courses").fetchone() == (0,)
                    assert db.execute(
                        "SELECT public.veriq_active_membership(gen_random_uuid(),'audit-fixture')"
                    ).fetchone() == (False,)
                    with db.transaction(force_rollback=True):
                        db.execute("SET LOCAL veriq.organization_id='audit-sentinel'")
                        db.execute("SET LOCAL veriq.user_id='audit-sentinel'")
                        assert db.execute(
                            "SELECT current_setting('veriq.user_id')"
                        ).fetchone() == ("audit-sentinel",)
                    assert db.execute(
                        "SELECT nullif(current_setting('veriq.user_id',true),'')"
                    ).fetchone() == (None,)
                    print(
                        "API login can set custom context; rollback clears transaction-local value"
                    )
                else:
                    denied(db, "SELECT * FROM courses")
                    denied(
                        db,
                        "SELECT public.veriq_active_membership(gen_random_uuid(),'audit-fixture')",
                    )
                    assert db.execute(
                        "SELECT public.veriq_import_purge()"
                    ).fetchone() == (0,)
                    with db.transaction(force_rollback=True):
                        db.execute(
                            "INSERT INTO background_jobs(id,kind,status) VALUES ('00000000-0000-0000-0000-000000000001','audit-fixture','succeeded')"
                        )
                        assert db.execute(
                            "UPDATE background_jobs SET kind='audit-modified',status='pending',attempts=2 WHERE kind='audit-fixture' RETURNING kind,status,attempts"
                        ).fetchone() == ("audit-modified", "pending", 2)
                        print("AUDIT FINDING: worker can rewrite a completed queue row")
                    denied(db, "DELETE FROM background_jobs WHERE false")


if __name__ == "__main__":
    main()
