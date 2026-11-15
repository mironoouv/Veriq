"""Verify the session-store lock prerequisites on a disposable PostgreSQL 17.11."""

from academic_catalog_checks import ADMIN, ORG, OTHER, OUTSIDER, role
from academic_group_teacher_schema_checks import expect_state, fixture
from sqlalchemy import text
from veriq.auth_credentials import CredentialVerifier
from veriq.database import create_database_engine
from veriq.sessions import Sessions

LOCK = """
    SELECT id FROM public.auth_sessions
    WHERE id=:id AND token_hash=:digest FOR NO KEY UPDATE NOWAIT
"""


def main() -> None:
    owner = create_database_engine()
    store = role("veriq_session_store")
    sessions = Sessions(role("veriq_api"), issuer=role("veriq_session_issuer"))
    verifier = CredentialVerifier(role("veriq_credential_verifier"))
    with owner.connect() as db:
        assert db.exec_driver_sql("SHOW server_version_num").scalar_one() == "170011"
        assert not db.exec_driver_sql(
            "SELECT EXISTS (SELECT FROM organizations)"
        ).scalar_one()
    fixture(owner)
    first, second = (
        sessions.issue(
            verifier.confirm(user, 1, mfa_level=1, organization_id=org)
        )._gate(sessions.policy)
        for user, org in ((ADMIN, ORG), (OUTSIDER, OTHER))
    )
    a = {"id": first.session_id, "digest": first.digest}
    b = {"id": second.session_id, "digest": second.digest}
    wrong = {"id": second.session_id, "digest": first.digest}
    with store.begin() as db:
        assert db.exec_driver_sql("""
            SELECT current_user, c.relrowsecurity,c.relforcerowsecurity,
                   r.rolbypassrls, r.rolsuper, r.rolcanlogin, pg_has_role(c.relowner,'MEMBER'),
                   has_column_privilege(c.oid,'id','SELECT'),
                   has_column_privilege(c.oid,'token_hash','SELECT'),
                   has_column_privilege(c.oid,'revoked_at','UPDATE'),
                   has_column_privilege(c.oid,'token_hash','UPDATE')
            FROM pg_class c JOIN pg_roles r ON r.rolname=current_user
            WHERE c.oid='public.auth_sessions'::regclass
        """).one() == (
            "veriq_session_store",
            False,
            False,
            False,
            False,
            False,
            False,
            True,
            True,
            True,
            False,
        )
        assert db.execute(text(LOCK), a).scalars().all() == [first.session_id]
        with store.begin() as contender:
            assert contender.exec_driver_sql(
                "SELECT pg_backend_pid()"
            ).scalar_one() != (
                db.exec_driver_sql("SELECT pg_backend_pid()").scalar_one()
            )
            expect_state(contender, LOCK, "55P03", **a)

    with store.begin() as holder:
        assert holder.execute(text(LOCK), b).scalars().all() == [second.session_id]
        with store.begin() as probe:
            assert probe.execute(text(LOCK), wrong).scalars().all() == []

    with store.begin() as probe:
        assert probe.execute(text(LOCK), wrong).scalars().all() == []
        with store.begin() as contender:
            assert contender.execute(text(LOCK), b).scalars().all() == [
                second.session_id
            ]
    print("Session-store ACL, RLS flags, 55P03 and mismatched proof passed")
    store.dispose()
    owner.dispose()


if __name__ == "__main__":
    main()
