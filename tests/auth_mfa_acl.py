"""Check MFA and independent recovery SQL entry point privileges."""

import sys
from uuid import uuid4

from auth_issuer_acl import DIGEST, ID, LIMITS, check, open_db

MFA = {"veriq_mfa_verifier"}
API = {"veriq_api"}
PURPOSE = "'fixture'::text"
POLICY_TYPES = "uuid,uuid,smallint,interval[]"
POLICY_ARGS = f"{ID},{ID},0::smallint,{LIMITS}"
INVOKERS = {
    f"veriq_base_session_limits({POLICY_TYPES})",
    f"veriq_session_limits({POLICY_TYPES})",
    f"veriq_pre_recovery_session_limits({POLICY_TYPES})",
    "veriq_recovery_permission(uuid,uuid,text)",
    "veriq_recovery_superadmin(uuid)",
}
FUNCTIONS = (
    ("veriq_mfa_primary(uuid,bytea,interval[])", f"{ID},{DIGEST},{LIMITS}", MFA),
    ("veriq_mfa_account(uuid,bigint)", f"{ID},1::bigint", MFA),
    ("veriq_pre_recovery_mfa_account(uuid,bigint)", f"{ID},1::bigint", set()),
    (
        "veriq_mfa_confirm(uuid,uuid,bigint,bytea,uuid)",
        f"{ID},{ID},1::bigint,{DIGEST},{ID}",
        MFA,
    ),
    ("veriq_mfa_can_disable(uuid,interval[])", f"{ID},{LIMITS}", MFA),
    ("veriq_mfa_reset_sessions(uuid)", ID, MFA),
    (
        "veriq_mfa_fresh(uuid,bytea,interval[],text,interval)",
        f"{ID},{DIGEST},{LIMITS},{PURPOSE},interval '5 minutes'",
        API | MFA,
    ),
    (
        "veriq_recovery_start(uuid,bytea,uuid,uuid,uuid)",
        f"{ID},{DIGEST},{ID},{ID},{ID}",
        API,
    ),
    (
        "veriq_recovery_transition(uuid,bytea,interval[],uuid,text,uuid,bytea,uuid,uuid)",
        f"{ID},{DIGEST},{LIMITS},{ID},{PURPOSE},{ID},{DIGEST},{ID},{ID}",
        API,
    ),
    (
        "veriq_recovery_enrollment(uuid,bytea,bytea,uuid,bytea,uuid,text,bytea)",
        f"{ID},{DIGEST},{DIGEST},{ID},{DIGEST},{ID},{PURPOSE},{DIGEST}",
        MFA,
    ),
    (
        "veriq_recovery_complete(uuid,bytea,bytea,bigint,bytea[],bytea[],uuid,uuid)",
        f"{ID},{DIGEST},{DIGEST},1::bigint,ARRAY[{DIGEST}],ARRAY[{DIGEST}],{ID},{ID}",
        MFA,
    ),
    (
        "veriq_recovery_reject(uuid,bytea,bytea,uuid,uuid)",
        f"{ID},{DIGEST},{DIGEST},{ID},{ID}",
        MFA,
    ),
    ("veriq_recovery_permission(uuid,uuid,text)", f"{ID},{ID},{PURPOSE}", set()),
    ("veriq_recovery_superadmin(uuid)", ID, set()),
    *tuple(
        (f"{name}({POLICY_TYPES})", POLICY_ARGS, set())
        for name in (
            "veriq_session_limits",
            "veriq_pre_recovery_session_limits",
            "veriq_base_session_limits",
        )
    ),
)


def recovery_trigger(database):
    with open_db(database) as owner:
        row = owner.execute("""
            SELECT p.proowner::regrole::text,p.prosecdef,p.proconfig,
              EXISTS(SELECT FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner)))
                     WHERE grantee=0 AND privilege_type='EXECUTE'),
              count(*) FILTER (WHERE t.tgenabled='O' AND NOT t.tgisinternal)
            FROM pg_proc p LEFT JOIN pg_trigger t ON t.tgfoid=p.oid
            WHERE p.oid='public.veriq_recovery_authority_changed()'::regprocedure
            GROUP BY p.oid
        """).fetchone()
        assert row == (
            "veriq_session_store",
            True,
            ["search_path=pg_catalog, pg_temp"],
            False,
            10,
        ), row


def authority_revocation(database):
    org, role = uuid4(), uuid4()
    with open_db(database) as owner, owner.transaction(force_rollback=True):
        owner.execute(
            "INSERT INTO organizations(id,slug,display_name,timezone,status) VALUES (%s,%s,'Fixture','UTC','active')",
            (org, org.hex),
        )
        owner.execute(
            "INSERT INTO organization_roles VALUES (%s,%s,'org_admin')", (org, role)
        )
        permission = owner.execute(
            "SELECT code FROM permissions WHERE code LIKE '%recovery%' AND scope='organization' LIMIT 1"
        ).fetchone()[0]
        owner.execute(
            "INSERT INTO organization_role_permissions VALUES (%s,%s,%s)",
            (org, role, permission),
        )
        revision = "SELECT revision FROM mfa_recovery_authority WHERE id"
        before = owner.execute(revision).fetchone()[0]
        assert (
            owner.execute(
                "DELETE FROM organization_role_permissions WHERE organization_id=%s AND role_id=%s AND permission_code=%s",
                (org, role, permission),
            ).rowcount
            == 1
        )
        assert owner.execute(revision).fetchone() == (before + 1,)
    print(f"{database}: revoking a recovery grant advances the authority revision")


def factor_acl(database):
    with open_db(database, "veriq_mfa_verifier") as db:
        assert db.execute("SELECT session_user,current_user").fetchone() == (
            "veriq_mfa_verifier",
            "veriq_mfa_verifier",
        )
        rows = db.execute("""
            SELECT relname, relrowsecurity, relforcerowsecurity,
                   has_table_privilege(current_user,oid,'INSERT'),
                   has_table_privilege(current_user,oid,'UPDATE'),
                   has_table_privilege(current_user,oid,'DELETE')
            FROM pg_class WHERE relnamespace='public'::regnamespace
              AND relname IN ('mfa_factors','mfa_recovery_codes','mfa_challenges','mfa_session_assurance')
            ORDER BY relname
        """).fetchall()
        assert len(rows) == 4
        assert all(row[1:] == (False, False, True, True, True) for row in rows), rows
        print(f"{database}: trusted verifier has direct factor DML; no table RLS")


def factor_dml(database):
    first, second = uuid4(), uuid4()
    with open_db(database) as owner, open_db(database, "veriq_mfa_verifier") as db:
        for account in (first, second):
            owner.execute(
                "INSERT INTO users(id,email_normalized,password_hash) VALUES (%s,%s,'fixture')",
                (account, f"{account.hex}@example.invalid"),
            )
        try:
            with db.transaction(force_rollback=True):
                for account in (first, second):
                    assert (
                        db.execute(
                            """
                        INSERT INTO mfa_factors(user_id,id,key_id,ciphertext,pending_until)
                        VALUES (%s,%s,'fixture',%s,now()+interval '5 minutes')
                    """,
                            (account, uuid4(), b"synthetic"),
                        ).rowcount
                        == 1
                    )
                assert (
                    db.execute(
                        "UPDATE mfa_factors SET confirmed_at=now() WHERE user_id=%s",
                        (second,),
                    ).rowcount
                    == 1
                )
                assert (
                    db.execute(
                        "DELETE FROM mfa_factors WHERE user_id=%s", (second,)
                    ).rowcount
                    == 1
                )
            assert owner.execute(
                "SELECT count(*) FROM mfa_factors WHERE user_id IN (%s,%s)",
                (first, second),
            ).fetchone() == (0,)
        finally:
            owner.execute("DELETE FROM users WHERE id IN (%s,%s)", (first, second))
    print(
        f"{database}: trusted MFA login performed synthetic factor DML without a session; rolled back"
    )


if __name__ == "__main__":
    for database in sys.argv[1:]:
        check(database, FUNCTIONS, invokers=INVOKERS)
        recovery_trigger(database)
        authority_revocation(database)
        factor_acl(database)
        factor_dml(database)
