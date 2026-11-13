"""Audit session SQL callers and the browser rotation/revocation contract."""

import sys
from uuid import uuid4

from auth_issuer_acl import DIGEST, ID, LIMITS, check, open_db

API = {"veriq_api"}
FUNCTIONS = (
    (
        "veriq_session_use(uuid,bytea,interval[],uuid,bytea,uuid)",
        f"{ID},{DIGEST},{LIMITS},{ID},{DIGEST},{ID}",
        API | {"veriq_mfa_verifier"},
    ),
    (
        "veriq_session_current(uuid,bytea,uuid,uuid,interval[])",
        f"{ID},{DIGEST},{ID},{ID},{LIMITS}",
        API | {"veriq_catalog_auditor"},
    ),
    (
        "veriq_session_revoke(uuid,bytea,interval[],boolean)",
        f"{ID},{DIGEST},{LIMITS},true",
        set(),
    ),
    (
        "veriq_auth_revoke(uuid,bytea,interval[],boolean,uuid,uuid,uuid)",
        f"{ID},{DIGEST},{LIMITS},true,{ID},{ID},{ID}",
        API,
    ),
    (
        "veriq_browser_rotate(uuid,bytea,interval[],uuid,bytea,uuid,uuid,uuid,uuid)",
        f"{ID},{DIGEST},{LIMITS},{ID},{DIGEST},{ID},{ID},{ID},{ID}",
        API,
    ),
)


def lifecycle(database):
    account, session, replacement, event = (uuid4() for _ in range(4))
    first, second = uuid4().bytes * 2, uuid4().bytes * 2
    with open_db(database) as owner, open_db(database, "veriq_api") as api:
        owner.execute(
            "INSERT INTO users(id,email_normalized,email_verified_at,password_hash) VALUES (%s,%s,now(),'fixture')",
            (account, f"{account.hex}@example.invalid"),
        )
        owner.execute(
            """
            INSERT INTO auth_sessions(id,user_id,token_hash,mfa_level,authenticated_at,
                created_at,last_seen_at,idle_expires_at,absolute_expires_at)
            VALUES (%s,%s,%s,0,now(),now(),now(),now()+interval '1 hour',now()+interval '2 hours')
        """,
            (session, account, first),
        )
        current = f"SELECT public.veriq_session_current(%s,%s,%s,NULL,{LIMITS})"
        rotate = f"SELECT user_id FROM public.veriq_browser_rotate(%s,%s,{LIMITS},%s,%s,NULL,%s,%s,%s)"
        revoke = f"SELECT public.veriq_auth_revoke(%s,%s,{LIMITS},%s,%s,%s,%s)"
        assert api.execute(current, (session, first, account)).fetchone() == (True,)
        assert api.execute(
            revoke, (session, second, True, event, event, event)
        ).fetchone() == (0,)
        assert (
            api.execute(
                rotate, (session, second, replacement, second, event, event, event)
            ).fetchone()
            is None
        )
        assert api.execute(
            rotate, (session, first, replacement, second, event, event, event)
        ).fetchone() == (account,)
        assert (
            api.execute(
                rotate,
                (session, first, uuid4(), uuid4().bytes * 2, uuid4(), event, event),
            ).fetchone()
            is None
        )
        assert api.execute(current, (session, first, account)).fetchone() == (False,)
        assert api.execute(current, (replacement, second, account)).fetchone() == (
            True,
        )
        revoke_event = uuid4()
        with api.transaction(force_rollback=True):
            assert api.execute(
                revoke,
                (replacement, second, True, revoke_event, revoke_event, revoke_event),
            ).fetchone() == (1,)
            assert api.execute(current, (replacement, second, account)).fetchone() == (
                False,
            )
        assert api.execute(current, (replacement, second, account)).fetchone() == (
            True,
        )
        assert owner.execute(
            "SELECT count(*) FROM auth_audit_events WHERE id=%s", (revoke_event,)
        ).fetchone() == (0,)
        assert api.execute(
            revoke,
            (replacement, second, True, revoke_event, revoke_event, revoke_event),
        ).fetchone() == (1,)
        assert api.execute(current, (replacement, second, account)).fetchone() == (
            False,
        )
        assert owner.execute(
            "SELECT credential_version FROM users WHERE id=%s", (account,)
        ).fetchone() == (2,)
        assert owner.execute(
            "SELECT event_type FROM auth_audit_events WHERE id=%s", (revoke_event,)
        ).fetchone() == ("sessions_revoked",)
        print(
            f"{database}: digest mismatch, rotation replay, atomic rollback and revoke-all passed"
        )


if __name__ == "__main__":
    for database in sys.argv[1:]:
        check(database, FUNCTIONS)
        lifecycle(database)
