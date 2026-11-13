"""Read effective privileges and exercise denied operations on synthetic databases."""

import os
import sys
from uuid import uuid4

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


def denied(db, statement: str, params=None) -> None:
    try:
        db.execute(statement, params)
    except errors.InsufficientPrivilege:
        print("Denied (42501):", statement)
    else:
        raise AssertionError(f"Expected permission denial: {statement}")


def queue_leases(db, database, password):
    job, first, second = uuid4(), uuid4(), uuid4()
    claim = "SELECT * FROM public.veriq_queue_claim(%s)"
    heartbeat = "SELECT public.veriq_queue_heartbeat(%s,%s,%s)"
    finish = "SELECT public.veriq_queue_finish(%s,%s,%s,%s)"
    db.execute("SELECT public.veriq_queue_enqueue(%s)", (job,))
    db.execute("SELECT public.veriq_queue_enqueue(%s)", (job,))
    with connection(database, "veriq_worker", password) as crashed:
        assert crashed.execute(claim, (first,)).fetchone() == (job, "probe", 1)
    with connection(database, "veriq_worker", password) as other:
        assert other.execute(claim, (second,)).fetchone() is None
        assert other.execute(heartbeat, (job, second, 1)).fetchone() == (False,)
        assert other.execute(finish, (job, second, 1, True)).fetchone() == (False,)
    with connection(database, "veriq_dev", os.environ["VERIQ_DB_PASSWORD"]) as owner:
        expiry = "SELECT lease_until FROM background_jobs WHERE id=%s"
        before = owner.execute(expiry, (job,)).fetchone()[0]
        assert db.execute(heartbeat, (job, first, 1)).fetchone() == (True,)
        assert owner.execute(expiry, (job,)).fetchone()[0] > before
        owner.execute(
            "UPDATE background_jobs SET lease_until=clock_timestamp()-interval '5 seconds' WHERE id=%s",
            (job,),
        )
        assert db.execute(heartbeat, (job, first, 1)).fetchone() == (False,)
        assert db.execute(claim, (second,)).fetchone() == (job, "probe", 2)
        assert db.execute(finish, (job, first, 1, True)).fetchone() == (False,)
        assert db.execute(heartbeat, (job, second, 1)).fetchone() == (False,)
        assert db.execute(finish, (job, second, 2, False)).fetchone() == (True,)
        assert db.execute(claim, (first,)).fetchone() is None
        owner.execute(
            "UPDATE background_jobs SET available_at=clock_timestamp() WHERE id=%s",
            (job,),
        )
        assert db.execute(claim, (first,)).fetchone() == (job, "probe", 3)
        assert db.execute(finish, (job, first, 3, True)).fetchone() == (True,)
        assert db.execute(finish, (job, first, 3, False)).fetchone() == (False,)
        assert db.execute(claim, (second,)).fetchone() is None
        assert owner.execute(
            "SELECT status,attempts FROM background_jobs WHERE id=%s", (job,)
        ).fetchone() == ("succeeded", 3)
        exhausted = uuid4()
        db.execute("SELECT public.veriq_queue_enqueue(%s)", (exhausted,))
        for token in range(1, 4):
            assert db.execute(claim, (first,)).fetchone() == (exhausted, "probe", token)
            owner.execute(
                "UPDATE background_jobs SET lease_until=clock_timestamp()-interval '10 seconds' WHERE id=%s",
                (exhausted,),
            )
        assert db.execute(claim, (second,)).fetchone() is None
        assert owner.execute(
            "SELECT status,attempts FROM background_jobs WHERE id=%s", (exhausted,)
        ).fetchone() == ("failed", 3)
    print(
        "Durable queue: committed claim, heartbeat, expiry, fencing, backoff and immutable success passed"
    )


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
            for case in ("valid", "digest", "expired", "revoked", "foreign"):
                sid, digest = uuid4(), uuid4().bytes + uuid4().bytes
                owner.execute(
                    """
                    INSERT INTO auth_sessions(
                        id,user_id,token_hash,organization_id,grant_epoch,mfa_level,
                        authenticated_at,created_at,last_seen_at,idle_expires_at,absolute_expires_at,
                        revoked_at,revoke_reason
                    )
                    SELECT %s,user_id,%s,organization_id,grant_epoch,1,
                        now()-interval '10 minutes',now()-interval '10 minutes',
                        now()-interval '10 minutes',
                        now()+CASE WHEN %s='expired' THEN interval '-1 minute' ELSE interval '5 minutes' END,
                        now()+interval '1 hour',
                        CASE WHEN %s='revoked' THEN now() END,
                        CASE WHEN %s='revoked' THEN 'logout' END
                    FROM organization_memberships
                    WHERE CASE WHEN %s='foreign' THEN organization_id<>%s
                               ELSE organization_id=%s AND user_id=%s END
                    LIMIT 1
                """,
                    (sid, digest, case, case, case, case, org, org, subject),
                )
                try:
                    with api.transaction(force_rollback=True):
                        api.execute(
                            """
                            SELECT set_config('veriq.organization_id',%s,true),
                                   set_config('veriq.user_id',%s,true),
                                   set_config('veriq.catalog_session_id',%s,true),
                                   set_config('veriq.catalog_session_digest',%s,true)
                        """,
                            (
                                str(org),
                                str(subject),
                                str(sid),
                                digest.hex() if case != "digest" else "00" * 32,
                            ),
                        )
                        update = "UPDATE courses SET title='Audit session fixture' WHERE id=%s AND organization_id=%s"
                        if case == "valid":
                            assert api.execute(update, (item, org)).rowcount == 1
                        else:
                            denied(api, update, (item, org))
                finally:
                    owner.execute("DELETE FROM auth_sessions WHERE id=%s", (sid,))
                assert (
                    owner.execute(
                        "SELECT count(*) FROM academic_catalog_events"
                    ).fetchone()
                    == before
                )
                print("Catalog session probe:", case)
            denied(api, "INSERT INTO academic_catalog_events DEFAULT VALUES")

            denied(api, "UPDATE academic_catalog_events SET action='edit' WHERE false")
            for dbname in (clean, upgraded):
                with connection(
                    dbname, "veriq_dev", os.environ["VERIQ_DB_PASSWORD"]
                ) as db:
                    assert (
                        db.execute("""
                        SELECT rolcanlogin,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolbypassrls
                        FROM pg_roles WHERE rolname='veriq_catalog_auditor'
                    """).fetchone()
                        == (False,) * 6
                    )
                    assert db.execute("""
                        SELECT count(*) FROM pg_auth_members
                        WHERE member='veriq_catalog_auditor'::regrole
                    """).fetchone() == (0,)

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
                    denied(
                        db, "SELECT * FROM public.veriq_queue_claim(gen_random_uuid())"
                    )
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
                    denied(db, "SELECT * FROM background_jobs")
                    denied(db, "INSERT INTO background_jobs DEFAULT VALUES")
                    denied(
                        db,
                        "UPDATE background_jobs SET kind='probe',status='pending',attempts=0,available_at=now()",
                    )
                    denied(db, "DELETE FROM background_jobs WHERE false")
                    queue_leases(db, database, os.environ[variable])


if __name__ == "__main__":
    main()
