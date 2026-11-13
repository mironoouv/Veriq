"""Read effective privileges and exercise denied operations on synthetic databases."""

import os
import sys

from psycopg import connect, errors



def connection(database: str, role: str, password: str):
    return connect(
        host=os.environ["VERIQ_DB_HOST"], dbname=database, user=role,
        password=password, autocommit=True,
    )


def inventory(database: str):
    with connection(database, "veriq_dev", os.environ["VERIQ_DB_PASSWORD"]) as db:
        assert db.execute("SHOW server_version_num").fetchone() == ("170011",)
        routines = db.execute("""
            SELECT p.oid::regprocedure::text, p.proowner::regrole::text,
                   p.proconfig, has_function_privilege('public',p.oid,'EXECUTE'),
                   ARRAY(SELECT rolname FROM pg_roles
                         WHERE rolname LIKE 'veriq_%%'
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
    for database in (clean, upgraded):
        for role, variable in (
            ("veriq_api", "VERIQ_API_DB_PASSWORD"),
            ("veriq_worker", "VERIQ_WORKER_DB_PASSWORD"),
        ):
            with connection(database, role, os.environ[variable]) as db:
                assert db.execute("SELECT session_user,current_user").fetchone() == (role, role)
                assert db.execute("""
                    SELECT rolsuper,rolbypassrls,rolcreaterole FROM pg_roles
                    WHERE rolname=current_user
                """).fetchone() == (False, False, False)
                denied(db, "SELECT * FROM auth_sessions")
                denied(db, "DELETE FROM academic_catalog_events WHERE false")
                if role == "veriq_api":
                    denied(db, "SELECT public.veriq_import_purge()")
                    assert db.execute("SELECT count(*) FROM courses").fetchone() == (0,)
                else:
                    denied(db, "SELECT * FROM courses")
                    denied(db, "SELECT public.veriq_active_membership(NULL::uuid,NULL::text)")
                    db.execute("SELECT count(*) FROM background_jobs").fetchone()
                    denied(db, "DELETE FROM background_jobs WHERE false")


if __name__ == "__main__":
    main()
