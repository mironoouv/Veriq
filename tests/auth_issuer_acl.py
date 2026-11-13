"""Contract for the first Auth SQL privilege review."""

import os
import sys
from uuid import uuid4

from psycopg import connect, errors, sql

LIMITS = (
    "ARRAY[interval '30 min',interval '8 hours',interval '2 hours',interval '12 hours']"
)
ID = "'00000000-0000-0000-0000-000000000001'::uuid"
DIGEST = "decode(repeat('00',32),'hex')"
ISSUE_ARGS = f"{ID},{DIGEST},{ID},{DIGEST},{LIMITS},{ID},{ID},{ID}"
ISSUE_TYPES = "uuid,bytea,uuid,bytea,interval[],uuid,uuid,uuid"
FUNCTIONS = (
    (
        "veriq_auth_confirm(uuid,uuid,bigint,bytea,uuid,smallint)",
        f"{ID},{ID},1::bigint,{DIGEST},{ID},0::smallint",
        {"veriq_credential_verifier"},
    ),
    (
        f"veriq_auth_issue({ISSUE_TYPES})",
        ISSUE_ARGS,
        {"veriq_session_issuer", "veriq_mfa_verifier"},
    ),
    (
        "veriq_password_candidate(text)",
        "'absent@example.invalid'::text",
        {"veriq_password_verifier"},
    ),
    (
        "veriq_password_confirm(uuid,uuid,bigint,bytea,uuid,text,text,uuid,uuid)",
        f"{ID},{ID},1::bigint,{DIGEST},{ID},'fixture'::text,'fixture'::text,{ID},{ID}",
        {"veriq_password_verifier"},
    ),
    (f"veriq_browser_issue({ISSUE_TYPES})", ISSUE_ARGS, {"veriq_browser_issuer"}),
    (
        "veriq_session_issue(uuid,uuid,bytea,uuid,smallint,interval[])",
        f"{ID},{ID},{DIGEST},{ID},0::smallint,{LIMITS}",
        set(),
    ),
    (
        "veriq_mfa_confirm(uuid,uuid,bigint,bytea,uuid)",
        f"{ID},{ID},1::bigint,{DIGEST},{ID}",
        {"veriq_mfa_verifier"},
    ),
)
LOGINS = {
    "veriq_api": "VERIQ_API_DB_PASSWORD",
    "veriq_worker": "VERIQ_WORKER_DB_PASSWORD",
    "veriq_password_verifier": "VERIQ_TEST_LOGIN_VERIFIER_PASSWORD",
    "veriq_browser_issuer": "VERIQ_TEST_LOGIN_ISSUER_PASSWORD",
    "veriq_mfa_verifier": "VERIQ_TEST_MFA_DB_PASSWORD",
}


def open_db(database, role="veriq_dev"):
    return connect(
        host=os.environ["VERIQ_DB_HOST"],
        dbname=database,
        user=role,
        password=os.environ[LOGINS.get(role, "VERIQ_DB_PASSWORD")],
        autocommit=True,
    )


def check(database, functions=FUNCTIONS, function_owner="veriq_session_store"):
    with open_db(database) as owner:
        assert owner.execute("SHOW server_version_num").fetchone() == ("170011",)
        owner.execute("CREATE ROLE audit_unprivileged NOLOGIN")
        try:
            for signature, arguments, allowed in functions:
                metadata = owner.execute(
                    """
                    SELECT proowner::regrole::text,prosecdef,proconfig,
                        ARRAY(SELECT rolname FROM pg_roles r
                              WHERE NOT rolsuper AND has_function_privilege(r.oid,p.oid,'EXECUTE')
                              ORDER BY rolname),
                        EXISTS(SELECT FROM aclexplode(coalesce(proacl,acldefault('f',proowner)))
                               WHERE grantee=0 AND privilege_type='EXECUTE')
                    FROM pg_proc p WHERE oid=%s::regprocedure
                """,
                    ("public." + signature,),
                ).fetchone()
                assert metadata == (
                    function_owner,
                    True,
                    ["search_path=pg_catalog, pg_temp"],
                    sorted(allowed | {function_owner}),
                    False,
                ), (signature, metadata)
                name = signature.split("(")[0]
                statement = sql.SQL("SELECT public.{}({})").format(
                    sql.Identifier(name), sql.SQL(arguments)
                )
                for role in sorted(
                    set(LOGINS)
                    | allowed
                    | {
                        "veriq_session_issuer",
                        "veriq_credential_verifier",
                        "audit_unprivileged",
                    }
                ):
                    with open_db(
                        database, role if role in LOGINS else "veriq_dev"
                    ) as caller:
                        with caller.transaction(force_rollback=True):
                            if role not in LOGINS:
                                caller.execute(
                                    sql.SQL("SET LOCAL ROLE {}").format(
                                        sql.Identifier(role)
                                    )
                                )
                            assert caller.execute("""
                                SELECT current_user,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb,rolreplication
                                FROM pg_roles WHERE rolname=current_user
                            """).fetchone() == (role, False, False, False, False, False)
                            try:
                                result = caller.execute(statement).fetchone()
                            except errors.InsufficientPrivilege:
                                assert role not in allowed, (signature, role)
                            else:
                                assert role in allowed, (signature, role, result)
                                assert result in (None, (False,), ("denied",), ("",)), (
                                    signature,
                                    result,
                                )
                print(
                    f"{database}: {signature}: allowed and denied calls match ACL contract"
                )
        finally:
            owner.execute("DROP ROLE audit_unprivileged")


def browser_issue_contract(database):
    account, proof = uuid4(), uuid4()
    digest = bytes(range(32))
    email = f"{account.hex}@example.invalid"
    with (
        open_db(database) as owner,
        open_db(database, "veriq_password_verifier") as verifier,
        open_db(database, "veriq_browser_issuer") as issuer,
    ):
        owner.execute(
            "INSERT INTO users(id,email_normalized,email_verified_at,password_hash) VALUES (%s,%s,now(),'fixture')",
            (account, email),
        )
        assert verifier.execute(
            "SELECT id FROM public.veriq_password_candidate(%s)", (email,)
        ).fetchone() == (account,)
        request = uuid4()
        assert verifier.execute(
            "SELECT public.veriq_password_confirm(%s,%s,1::bigint,%s,NULL,'fixture',NULL,%s,%s)",
            (proof, account, digest, request, request),
        ).fetchone() == (True,)

        def issue(proof_digest, expected):
            session, event = uuid4(), uuid4()
            assert issuer.execute(
                f"SELECT public.veriq_browser_issue(%s,%s,%s,%s,{LIMITS},%s,%s,%s)",
                (proof, proof_digest, session, digest, event, event, event),
            ).fetchone() == (expected,)
            issued = expected == "issued"
            assert owner.execute(
                "SELECT count(*) FROM auth_sessions WHERE id=%s", (session,)
            ).fetchone() == (int(issued),)
            assert owner.execute(
                "SELECT event_type FROM auth_audit_events WHERE id=%s", (event,)
            ).fetchone() == (("session_issued",) if issued else None)

        issue(bytes(32), "denied")
        issue(digest, "issued")
        issue(digest, "denied")
        assert owner.execute(
            "SELECT event_type FROM auth_audit_events WHERE id=%s", (request,)
        ).fetchone() == ("password_verified",)
        for scenario in ("expired", "stale"):
            proof, request = uuid4(), uuid4()
            assert verifier.execute(
                "SELECT public.veriq_password_confirm(%s,%s,1::bigint,%s,NULL,'fixture',NULL,%s,%s)",
                (proof, account, digest, request, request),
            ).fetchone() == (True,)
            if scenario == "expired":
                owner.execute(
                    "UPDATE auth_credential_proofs SET expires_at=now() WHERE id=%s",
                    (proof,),
                )
            else:
                owner.execute(
                    "UPDATE users SET credential_version=2 WHERE id=%s", (account,)
                )
            issue(digest, "denied")
        print(
            f"{database}: browser proof digest, issuance, replay, expiry, stale version and audit passed"
        )


if __name__ == "__main__":
    for database_name in sys.argv[1:]:
        check(database_name)
        browser_issue_contract(database_name)
