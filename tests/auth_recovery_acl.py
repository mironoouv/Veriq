"""Audit the signup and password recovery boundaries in disposable databases."""

import sys
from uuid import uuid4

from auth_issuer_acl import DIGEST, ID, LIMITS, check, open_db

EMAIL = "'absent@example.invalid'::text"
VALUE = "'synthetic'::text"
API = {"veriq_api"}
WORKER = {"veriq_worker"}
VERIFIER = {"veriq_password_verifier"}
SIGNUP = (
    (
        "veriq_signup_start(uuid,text,text,uuid,bytea,bytea)",
        f"{ID},{EMAIL},{VALUE},{ID},{DIGEST},{DIGEST}",
        API,
    ),
    (
        "veriq_signup_resend(text,uuid,bytea,bytea)",
        f"{EMAIL},{ID},{DIGEST},{DIGEST}",
        API,
    ),
    (
        "veriq_signup_verify(uuid,bytea,text,text)",
        f"{ID},{DIGEST},{EMAIL},{VALUE}",
        API,
    ),
    ("veriq_signup_mail_next()", "", WORKER),
    ("veriq_signup_mail_finish(uuid,boolean)", f"{ID},true", WORKER),
)
PASSWORD = (
    ("veriq_password_notice_claim(uuid)", ID, WORKER),
    (
        "veriq_password_session_candidate(uuid,bytea,interval[])",
        f"{ID},{DIGEST},{LIMITS}",
        VERIFIER,
    ),
    (
        "veriq_password_change(uuid,bytea,interval[],bigint,text,text,uuid,uuid)",
        f"{ID},{DIGEST},{LIMITS},1::bigint,{VALUE},{VALUE},{ID},{ID}",
        VERIFIER,
    ),
    (
        "veriq_password_reset_start(text,uuid,bytea,bytea)",
        f"{EMAIL},{ID},{DIGEST},{DIGEST}",
        API,
    ),
    (
        "veriq_password_reset_finish(uuid,bytea,text,text,uuid,uuid)",
        f"{ID},{DIGEST},{EMAIL},{VALUE},{ID},{ID}",
        API,
    ),
    (
        "veriq_password_apply(uuid,text,text,uuid,uuid)",
        f"{ID},{VALUE},{VALUE},{ID},{ID}",
        set(),
    ),
)


def lifecycle(database):
    user, proof = uuid4(), uuid4()
    email = f"{user.hex}@example.invalid"
    digest = bytes(range(32))
    with open_db(database) as owner, open_db(database, "veriq_api") as api:
        api.execute(
            "SELECT public.veriq_signup_start(%s,%s,%s,%s,%s,%s)",
            (user, email, "initial", proof, digest, b"synthetic"),
        )
        verify = "SELECT public.veriq_signup_verify(%s,%s,%s,'verified')"
        assert api.execute(
            verify, (proof, digest, "other@example.invalid")
        ).fetchone() == (False,)
        owner.execute(
            "UPDATE email_verification_proofs SET expires_at=pending_since WHERE id=%s",
            (proof,),
        )
        assert api.execute(verify, (proof, digest, email)).fetchone() == (False,)
        replacement = uuid4()
        api.execute(
            "SELECT public.veriq_signup_resend(%s,%s,%s,%s)",
            (email, replacement, digest, b"synthetic"),
        )
        assert api.execute(verify, (proof, digest, email)).fetchone() == (False,)
        assert api.execute(verify, (replacement, digest, email)).fetchone() == (True,)
        assert api.execute(verify, (replacement, digest, email)).fetchone() == (False,)
        for case in ("expired", "stale", "valid"):
            reset, request = uuid4(), uuid4()
            api.execute(
                "SELECT public.veriq_password_reset_start(%s,%s,%s,%s)",
                (email, reset, digest, b"synthetic"),
            )
            finish = (
                "SELECT public.veriq_password_reset_finish(%s,%s,%s,'changed',%s,%s)"
            )
            assert api.execute(
                finish, (reset, bytes(32), email, request, request)
            ).fetchone() == (False,)
            assert api.execute(
                finish, (reset, digest, "other@example.invalid", request, request)
            ).fetchone() == (False,)
            if case == "expired":
                owner.execute(
                    "UPDATE password_reset_proofs SET expires_at=now() WHERE id=%s",
                    (reset,),
                )
            if case == "stale":
                owner.execute(
                    "UPDATE users SET credential_version=credential_version+1 WHERE id=%s",
                    (user,),
                )
            assert api.execute(
                finish, (reset, digest, email, request, request)
            ).fetchone() == (case == "valid",)
            assert api.execute(
                finish, (reset, digest, email, request, request)
            ).fetchone() == (False,)
            assert owner.execute(
                "SELECT event_type FROM auth_audit_events WHERE request_id=%s",
                (request,),
            ).fetchone() == (("password_reset",) if case == "valid" else None)
        assert owner.execute(
            "SELECT count(*) FROM auth_sessions WHERE user_id=%s", (user,)
        ).fetchone() == (0,)
    print(f"{database}: signup, expiry, resend, replay, reset version and audit passed")


if __name__ == "__main__":
    for database in sys.argv[1:]:
        check(database, SIGNUP, "veriq_signup_store")
        check(
            database,
            PASSWORD,
            invokers={"veriq_password_apply(uuid,text,text,uuid,uuid)"},
        )
        lifecycle(database)
