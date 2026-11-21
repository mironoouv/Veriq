"""Verify the proposed EXECUTE chain on a disposable migrated PostgreSQL."""

from academic_catalog_checks import role
from academic_group_teacher_schema_checks import expect_state
from sqlalchemy import text
from veriq.database import create_database_engine

SCHEMA = "veriq_test_execute"
API = "veriq_test_api"
WORKER = "veriq_test_worker"
COMMAND = "veriq_test_command"
ACCOUNTS = "veriq_test_accounts"
SESSIONS = "veriq_test_sessions"
ROLES = (API, WORKER, COMMAND, ACCOUNTS, SESSIONS)

# PostgreSQL owners retain implicit EXECUTE on their own functions.
FUNCTIONS = {
    "read_session": (SESSIONS, ACCOUNTS, ()),
    "lock_session": (SESSIONS, COMMAND, ()),
    "check_accounts": (ACCOUNTS, COMMAND, ("read_session",)),
    "transfer": (COMMAND, API, ("lock_session", "check_accounts")),
}


def signature(name: str) -> str:
    return f"{SCHEMA}.{name}(integer)"


def expected_chain(name: str) -> str:
    owner, _, children = FUNCTIONS[name]
    return ">".join([owner, *(expected_chain(child) for child in children)])


def main() -> None:
    owner = create_database_engine()
    try:
        with owner.begin() as db:
            assert (
                db.exec_driver_sql("SHOW server_version_num").scalar_one() == "170011"
            )
            assert db.exec_driver_sql(
                "SELECT version_num FROM public.alembic_version"
            ).scalar_one()
            assert not db.exec_driver_sql(
                "SELECT EXISTS (SELECT FROM organizations)"
            ).scalar_one()
            db.exec_driver_sql(f"CREATE SCHEMA {SCHEMA}")
            for actor in ROLES:
                db.exec_driver_sql(
                    f"CREATE ROLE {actor} NOLOGIN NOSUPERUSER NOBYPASSRLS"
                )
                db.exec_driver_sql(f"GRANT USAGE ON SCHEMA {SCHEMA} TO {actor}")
            for name, (function_owner, caller, children) in FUNCTIONS.items():
                calls = "\n".join(
                    f"trace := trace || '>' || {SCHEMA}.{child}(marker);"
                    for child in children
                )
                db.exec_driver_sql(f"""
                    CREATE FUNCTION {SCHEMA}.{name}(marker integer) RETURNS text
                    LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, pg_temp
                    AS $body$
                    DECLARE trace text := current_user::text;
                    BEGIN
                        {calls}
                        RETURN trace;
                    END;
                    $body$
                """)
                db.exec_driver_sql(
                    f"ALTER FUNCTION {signature(name)} OWNER TO {function_owner}"
                )
                db.exec_driver_sql(
                    f"REVOKE ALL ON FUNCTION {signature(name)} FROM PUBLIC"
                )
                db.exec_driver_sql(
                    f"GRANT EXECUTE ON FUNCTION {signature(name)} TO {caller}"
                )
                assert db.execute(
                    text("""
                    SELECT pg_get_userbyid(p.proowner), p.prosecdef,
                           EXISTS (SELECT FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner)))
                                   WHERE grantee=0 AND privilege_type='EXECUTE')
                    FROM pg_proc AS p WHERE p.oid=CAST(:signature AS regprocedure)
                """),
                    {"signature": signature(name)},
                ).one() == (function_owner, True, False)

        for actor in ROLES:
            engine = role(actor)
            try:
                with engine.begin() as db:
                    db.exec_driver_sql("SET LOCAL statement_timeout = '5s'")
                    assert (
                        db.exec_driver_sql("SELECT current_user").scalar_one() == actor
                    )
                    for name, (function_owner, caller, _) in FUNCTIONS.items():
                        allowed = actor in (function_owner, caller)
                        assert (
                            db.scalar(
                                text("""
                            SELECT has_function_privilege(
                                CAST(:signature AS regprocedure)::oid, 'EXECUTE'
                            )
                        """),
                                {"signature": signature(name)},
                            )
                            is allowed
                        )
                        call = f"SELECT {SCHEMA}.{name}(1)"
                        if allowed:
                            assert db.exec_driver_sql(
                                call
                            ).scalar_one() == expected_chain(name)
                            assert (
                                db.exec_driver_sql("SELECT current_user").scalar_one()
                                == actor
                            )
                        else:
                            expect_state(db, call, "42501")
            finally:
                engine.dispose()
        print("EXECUTE matrix, nested SECURITY DEFINER roles and SQLSTATE 42501 passed")
    finally:
        owner.dispose()


if __name__ == "__main__":
    main()
