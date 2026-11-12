"""Slice D PostgreSQL checks using the real API login and isolated fixtures."""

import os
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from hashlib import sha256
from threading import Barrier
from uuid import UUID

from sqlalchemy import Connection, Engine, create_engine, event, text
from sqlalchemy.exc import DBAPIError
from veriq.database import create_database_engine, database_url
from veriq.sessions import MfaLevel, SessionPolicy, Sessions, SessionToken
from veriq.tenant_access import (
    AccessDenied,
    ResourcePolicy,
    TenantResource,
    VerifiedSubject,
)

A, B = (UUID(int=value) for value in (101, 102))
MULTI, OUTSIDER, SUPERADMIN = (
    VerifiedSubject(UUID(int=value)) for value in (701, 702, 603)
)
ROLE_ADMIN, ROLE_STUDENT, ROLE_TECH = (UUID(int=value) for value in (401, 403, 450))
MEMBER_A, MEMBER_B = (UUID(int=value) for value in (711, 712))
ADMIN_POLICY = ResourcePolicy("fixture.admin")
STUDENT_POLICY = ResourcePolicy("fixture.learn")


def seed(owner: Engine) -> None:
    with owner.begin() as connection:
        for index, subject in enumerate((MULTI, OUTSIDER)):
            connection.execute(
                text("""
                INSERT INTO users (id, email_normalized, password_hash)
                VALUES (:id, :email, 'fixture-only-no-password')
            """),
                {
                    "id": subject.user_id,
                    "email": f"session-fixture-{index}@example.invalid",
                },
            )
        for org, member, role in (
            (A, MEMBER_A, ROLE_ADMIN),
            (B, MEMBER_B, ROLE_STUDENT),
        ):
            values = {"org": org, "member": member, "role": role, "user": MULTI.user_id}
            connection.execute(
                text("""
                INSERT INTO organization_memberships (organization_id, user_id, id, status)
                VALUES (:org, :user, :member, 'active')
            """),
                values,
            )
            connection.execute(
                text("""
                INSERT INTO membership_roles (organization_id, membership_id, role_id)
                VALUES (:org, :member, :role)
            """),
                values,
            )


def denied(operation: Callable[[], object]) -> None:
    try:
        operation()
    except AccessDenied:
        return
    raise AssertionError("Expected session or tenant access denial")


def session_id(token: SessionToken) -> UUID:
    return UUID(hex=token.value[:32])


def lifecycle_checks(owner: Engine, sessions: Sessions) -> None:
    token = sessions.issue(MULTI, mfa_level=MfaLevel.PRIMARY, organization_id=B)
    assert token.value not in repr(token)
    assert sessions.resolve(token).user_id == MULTI.user_id
    with owner.begin() as connection:
        row = connection.execute(
            text("""
            SELECT token_hash, idle_expires_at - last_seen_at AS idle,
                   absolute_expires_at - authenticated_at AS absolute
            FROM auth_sessions WHERE id = :id
        """),
            {"id": session_id(token)},
        ).one()
        assert row.token_hash == sha256(token.value.encode("ascii")).digest()
        assert row.idle == timedelta(hours=2)
        assert row.absolute == timedelta(hours=12)
    fake = SessionToken(
        token.value[:33] + ("A" if token.value[33] != "A" else "B") + token.value[34:]
    )
    denied(lambda: sessions.resolve(fake))
    assert sessions.revoke(fake) == 0
    assert sessions.revoke(token) == 1
    assert sessions.revoke(token) == 0
    denied(lambda: sessions.resolve(token))
    denied(lambda: sessions.rotate(token, organization_id=B))

    first = sessions.issue(MULTI, mfa_level=MfaLevel.PRIMARY)
    second = sessions.issue(MULTI, mfa_level=MfaLevel.PRIMARY, organization_id=B)
    other = sessions.issue(OUTSIDER, mfa_level=MfaLevel.PRIMARY)
    assert sessions.revoke(token, all_for_account=True) == 0
    assert sessions.revoke(first, all_for_account=True) == 2
    denied(lambda: sessions.resolve(first))
    denied(lambda: sessions.resolve(second))
    assert sessions.resolve(other).user_id == OUTSIDER.user_id


def expiry_checks(owner: Engine, sessions: Sessions, api: Engine) -> None:
    idle = sessions.issue(MULTI, mfa_level=MfaLevel.PRIMARY)
    absolute = sessions.issue(MULTI, mfa_level=MfaLevel.PRIMARY)
    with owner.begin() as connection:
        connection.execute(
            text("""
            UPDATE auth_sessions SET authenticated_at = now() - interval '3 hours',
                created_at = now() - interval '3 hours', last_seen_at = now() - interval '3 hours',
                idle_expires_at = now() - interval '1 hour' WHERE id = :id
        """),
            {"id": session_id(idle)},
        )
        # The new policy cuts the absolute cap while the stored and current idle limits are still valid.
        connection.execute(
            text("""
            UPDATE auth_sessions SET authenticated_at = now() - interval '3 hours',
                created_at = now() - interval '3 hours' WHERE id = :id
        """),
            {"id": session_id(absolute)},
        )
    denied(lambda: sessions.resolve(idle))
    shorter = Sessions(api, SessionPolicy(ordinary_absolute=timedelta(hours=2)))
    denied(lambda: shorter.resolve(absolute))
    assert sessions.resolve(absolute).user_id == MULTI.user_id
    with owner.begin() as connection:
        connection.execute(
            text("""
            UPDATE auth_sessions
            SET last_seen_at = now() - interval '1 hour',
                idle_expires_at = now() - interval '1 second',
                absolute_expires_at = now() - interval '1 second'
            WHERE id = :id
        """),
            {"id": session_id(absolute)},
        )
    denied(lambda: sessions.resolve(absolute))


def tenant_checks(owner: Engine, sessions: Sessions) -> None:
    denied(lambda: sessions.issue(MULTI, mfa_level=MfaLevel.PRIMARY, organization_id=A))
    denied(
        lambda: sessions.issue(OUTSIDER, mfa_level=MfaLevel.VERIFIED, organization_id=B)
    )
    denied(
        lambda: sessions.issue(
            SUPERADMIN, mfa_level=MfaLevel.VERIFIED, organization_id=A
        )
    )
    primary = sessions.issue(MULTI, mfa_level=MfaLevel.PRIMARY, organization_id=B)
    denied(lambda: sessions.rotate(primary, organization_id=A))
    assert sessions.resolve(primary).organization_id == B
    with sessions.tenant(primary) as access:
        access.require(STUDENT_POLICY, TenantResource(B))
        denied(lambda: access.require(ADMIN_POLICY, TenantResource(A)))
        assert set(
            access.connection.execute(text("SELECT id FROM organizations")).scalars()
        ) == {B}
        with owner.begin() as connection:
            connection.execute(
                text("""
                INSERT INTO membership_roles (organization_id, membership_id, role_id)
                VALUES (:org, :member, :role)
            """),
                {"org": B, "member": MEMBER_B, "role": ROLE_TECH},
            )
        denied(lambda: access.require(STUDENT_POLICY, TenantResource(B)))
    with owner.begin() as connection:
        connection.execute(
            text("""
            DELETE FROM membership_roles WHERE organization_id = :org AND membership_id = :member AND role_id = :role
        """),
            {"org": B, "member": MEMBER_B, "role": ROLE_TECH},
        )

    admin = sessions.issue(MULTI, mfa_level=MfaLevel.VERIFIED, organization_id=A)
    with sessions.tenant(admin) as access:
        access.require(ADMIN_POLICY, TenantResource(A))
        denied(lambda: access.require(STUDENT_POLICY, TenantResource(B)))
    rotated = sessions.rotate(admin, organization_id=B)
    denied(lambda: sessions.resolve(admin))
    assert sessions.resolve(rotated).organization_id == B
    with owner.begin() as connection:
        expiry = connection.execute(
            text("""
            SELECT absolute_expires_at - authenticated_at
            FROM auth_sessions WHERE id = :id
        """),
            {"id": session_id(rotated)},
        ).scalar_one()
        assert expiry == timedelta(hours=8)
    with sessions.tenant(rotated) as access:
        access.require(STUDENT_POLICY, TenantResource(B))

    with owner.begin() as connection:
        connection.execute(
            text("UPDATE users SET disabled_at = now() WHERE id = :id"),
            {"id": MULTI.user_id},
        )
    denied(lambda: sessions.resolve(rotated))
    with owner.begin() as connection:
        connection.execute(
            text("UPDATE users SET disabled_at = NULL WHERE id = :id"),
            {"id": MULTI.user_id},
        )
        connection.execute(
            text(
                "UPDATE organization_memberships SET status = 'suspended' WHERE id = :id"
            ),
            {"id": MEMBER_B},
        )
    denied(lambda: sessions.resolve(rotated))
    with owner.begin() as connection:
        connection.execute(
            text(
                "UPDATE organization_memberships SET status = 'revoked' WHERE id = :id"
            ),
            {"id": MEMBER_B},
        )
        connection.execute(
            text(
                "UPDATE organization_memberships SET status = 'active' WHERE id = :id"
            ),
            {"id": MEMBER_B},
        )
    denied(lambda: sessions.resolve(rotated))


def concurrency_checks(owner: Engine, sessions: Sessions) -> None:
    token = sessions.issue(MULTI, mfa_level=MfaLevel.PRIMARY)
    read_activity = text(
        "SELECT last_seen_at, absolute_expires_at FROM auth_sessions WHERE id = :id"
    )
    with owner.begin() as connection:
        before = connection.execute(read_activity, {"id": session_id(token)}).one()
    start = Barrier(4, timeout=10)

    def touch(_: int) -> UUID:
        start.wait()
        return sessions.resolve(token).user_id

    with ThreadPoolExecutor(max_workers=4) as executor:
        assert list(executor.map(touch, range(4))) == [MULTI.user_id] * 4
    with owner.begin() as connection:
        after = connection.execute(read_activity, {"id": session_id(token)}).one()
        assert after.last_seen_at > before.last_seen_at
        assert after.absolute_expires_at == before.absolute_expires_at
    rotate_start = Barrier(2, timeout=10)

    def rotate(_: int) -> SessionToken | None:
        rotate_start.wait()
        try:
            return sessions.rotate(token, organization_id=None)
        except AccessDenied:
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = [
            result for result in executor.map(rotate, range(2)) if result is not None
        ]
    assert len(results) == 1
    denied(lambda: sessions.resolve(token))
    assert sessions.resolve(results[0]).user_id == MULTI.user_id


def assert_sql_denial(engine: Engine, query: str) -> None:
    try:
        with engine.begin() as connection:
            connection.execute(text(query))
    except DBAPIError as error:
        assert getattr(error.orig, "sqlstate", None) == "42501"
    else:
        raise AssertionError("Expected PostgreSQL insufficient privilege")


def main() -> None:
    url = database_url()
    assert url.database is not None and url.database.startswith("memberships_test_")
    owner = create_database_engine()
    issuer = create_database_engine()

    @event.listens_for(issuer, "begin")
    def assume_fixture_issuer(connection: Connection) -> None:
        # Test-only role assumption in the disposable database.
        connection.exec_driver_sql("SET LOCAL ROLE veriq_session_issuer")

    api = create_engine(
        url.set(username="veriq_api", password=os.environ["VERIQ_API_DB_PASSWORD"]),
        hide_parameters=True,
    )
    worker = create_engine(
        url.set(
            username="veriq_worker", password=os.environ["VERIQ_WORKER_DB_PASSWORD"]
        ),
        hide_parameters=True,
    )
    try:
        seed(owner)
        sessions = Sessions(api, SessionPolicy(), issuer=issuer)
        assert_sql_denial(api, "SELECT token_hash FROM auth_sessions")
        assert_sql_denial(
            api, "SELECT public.veriq_session_issue(NULL, NULL, NULL, NULL, NULL, NULL)"
        )
        assert_sql_denial(issuer, "SELECT token_hash FROM auth_sessions")
        assert_sql_denial(
            worker, "SELECT public.veriq_session_revoke(NULL, NULL, NULL, false)"
        )
        lifecycle_checks(owner, sessions)
        expiry_checks(owner, sessions, api)
        tenant_checks(owner, sessions)
        concurrency_checks(owner, sessions)
        print(
            "Sessions smoke: hashing, expiry, revoke, rotation, organization MFA, RLS and concurrency passed."
        )
    finally:
        worker.dispose()
        api.dispose()
        issuer.dispose()
        owner.dispose()


if __name__ == "__main__":
    main()
