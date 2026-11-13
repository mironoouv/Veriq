"""Exercise staged MFA attestation using an isolated PostgreSQL login."""

import os
import sys
from uuid import uuid4

from auth_issuer_acl import DIGEST, ID, LOGINS, check, open_db
from psycopg import sql

LOGINS["veriq_mfa_trusted"] = "VERIQ_TEST_MFA_TRUSTED_PASSWORD"
FUNCTIONS = (
    (
        "veriq_trusted_mfa_attest(uuid,uuid,uuid,uuid,bytea,uuid)",
        f"{ID},{ID},{ID},{ID},{DIGEST},{ID}",
        {"veriq_mfa_trusted"},
    ),
    (
        "veriq_trusted_mfa_disable(uuid,uuid,uuid,uuid,bytea,uuid,uuid)",
        f"{ID},{ID},{ID},{ID},{DIGEST},{ID},{ID}",
        {"veriq_mfa_trusted"},
    ),
)


def lifecycle(database):
    account, factor, session = uuid4(), uuid4(), uuid4()
    digest = uuid4().bytes + uuid4().bytes
    with open_db(database) as owner, open_db(database, "veriq_mfa_trusted") as trusted:
        owner.execute(
            "INSERT INTO users(id,email_normalized,password_hash,email_verified_at) VALUES (%s,%s,'fixture',now())",
            (account, f"{account.hex}@example.invalid"),
        )
        owner.execute(
            """
            INSERT INTO mfa_factors(user_id,id,key_id,ciphertext,confirmed_at,pending_until)
            VALUES (%s,%s,'fixture',%s,now(),now()+interval '10 minutes')
        """,
            (account, factor, b"synthetic"),
        )
        owner.execute(
            """
            INSERT INTO auth_sessions(id,user_id,token_hash,mfa_level,authenticated_at,created_at,last_seen_at,idle_expires_at,absolute_expires_at)
            VALUES (%s,%s,%s,1,now(),now(),now(),now()+interval '30 minutes',now()+interval '1 hour')
        """,
            (session, account, digest),
        )
        attest = "SELECT public.veriq_trusted_mfa_attest(%s,%s,%s,%s,%s,NULL)"
        consume = "SELECT public.veriq_trusted_mfa_disable(%s,%s,%s,%s,%s,%s,%s)"
        expired, valid = uuid4(), uuid4()
        for proof in (expired, valid):
            assert trusted.execute(
                attest, (proof, account, factor, session, digest)
            ).fetchone() == (True,)
        owner.execute(
            "UPDATE mfa_operation_attestations SET expires_at=now() WHERE id=%s",
            (expired,),
        )
        event = uuid4()
        assert trusted.execute(
            consume, (expired, account, factor, session, digest, event, event)
        ).fetchone() == (False,)
        assert trusted.execute(
            consume, (valid, account, uuid4(), session, digest, event, event)
        ).fetchone() == (False,)
        with trusted.transaction(force_rollback=True):
            assert trusted.execute(
                consume, (valid, account, factor, session, digest, event, event)
            ).fetchone() == (True,)
        assert owner.execute(
            "SELECT consumed_at FROM mfa_operation_attestations WHERE id=%s", (valid,)
        ).fetchone() == (None,)
        assert owner.execute(
            "SELECT count(*) FROM mfa_factors WHERE id=%s", (factor,)
        ).fetchone() == (1,)
        assert owner.execute(
            "SELECT count(*) FROM auth_audit_events WHERE id=%s", (event,)
        ).fetchone() == (0,)
        assert trusted.execute(
            consume, (valid, account, factor, session, digest, event, event)
        ).fetchone() == (True,)
        assert trusted.execute(
            consume, (valid, account, factor, session, digest, event, event)
        ).fetchone() == (False,)
        assert owner.execute(
            "SELECT count(*) FROM auth_audit_events WHERE id=%s", (event,)
        ).fetchone() == (1,)
        print(
            f"{database}: expiry, factor binding, atomic rollback, successful disable and replay denial"
        )


if __name__ == "__main__":
    clean, upgraded = sys.argv[1:]
    with open_db(clean) as admin:
        admin.execute(
            sql.SQL("ALTER ROLE veriq_mfa_trusted LOGIN PASSWORD {}").format(
                sql.Literal(os.environ[LOGINS["veriq_mfa_trusted"]])
            )
        )
    for database in (clean, upgraded):
        check(database, FUNCTIONS)
        lifecycle(database)
