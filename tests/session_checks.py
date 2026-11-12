"""Slice D PostgreSQL checks using the real API login and isolated fixtures."""

import os
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import timedelta
from hashlib import sha256
from threading import Barrier
from uuid import UUID, uuid4

from sqlalchemy import Connection, Engine, create_engine, event, text
from sqlalchemy.exc import DBAPIError
from veriq.auth_audit import (
    AuthEvent,
    AuthResult,
    Notice,
    RequestContext,
    acknowledge_notice,
    append_attempt,
    claim_notice,
)
from veriq.auth_credentials import CredentialProof, CredentialVerifier
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


def lifecycle_checks(owner: Engine, issuance: "Issuance") -> None:
    sessions = issuance.sessions
    token = issuance.issue(MULTI, mfa_level=MfaLevel.PRIMARY, organization_id=B)
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

    first = issuance.issue(MULTI, mfa_level=MfaLevel.PRIMARY)
    second = issuance.issue(MULTI, mfa_level=MfaLevel.PRIMARY, organization_id=B)
    other = issuance.issue(OUTSIDER, mfa_level=MfaLevel.PRIMARY)
    assert sessions.revoke(token, all_for_account=True) == 0
    assert sessions.revoke(first, all_for_account=True) == 2
    denied(lambda: sessions.resolve(first))
    denied(lambda: sessions.resolve(second))
    assert sessions.resolve(other).user_id == OUTSIDER.user_id


def expiry_checks(owner: Engine, issuance: "Issuance", api: Engine) -> None:
    sessions = issuance.sessions
    idle = issuance.issue(MULTI, mfa_level=MfaLevel.PRIMARY)
    absolute = issuance.issue(MULTI, mfa_level=MfaLevel.PRIMARY)
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


def tenant_checks(owner: Engine, issuance: "Issuance") -> None:
    sessions = issuance.sessions
    denied(lambda: issuance.issue(MULTI, mfa_level=MfaLevel.PRIMARY, organization_id=A))
    denied(
        lambda: issuance.issue(OUTSIDER, mfa_level=MfaLevel.VERIFIED, organization_id=B)
    )
    denied(
        lambda: issuance.issue(
            SUPERADMIN, mfa_level=MfaLevel.VERIFIED, organization_id=A
        )
    )
    primary = issuance.issue(MULTI, mfa_level=MfaLevel.PRIMARY, organization_id=B)
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

    admin = issuance.issue(MULTI, mfa_level=MfaLevel.VERIFIED, organization_id=A)
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


def concurrency_checks(owner: Engine, issuance: "Issuance") -> None:
    sessions = issuance.sessions
    token = issuance.issue(MULTI, mfa_level=MfaLevel.PRIMARY)
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


@dataclass(frozen=True)
class Issuance:
    sessions: Sessions
    verifier: CredentialVerifier
    owner: Engine

    def proof(
        self,
        subject: VerifiedSubject,
        *,
        mfa_level: MfaLevel = MfaLevel.PRIMARY,
        organization_id: UUID | None = None,
    ) -> CredentialProof:
        with self.owner.connect() as connection:
            version = connection.execute(
                text("SELECT credential_version FROM users WHERE id = :id"),
                {"id": subject.user_id},
            ).scalar_one()
        return self.verifier.confirm(
            subject.user_id,
            version,
            mfa_level=mfa_level,
            organization_id=organization_id,
        )

    def issue(
        self,
        subject: VerifiedSubject,
        *,
        mfa_level: MfaLevel,
        organization_id: UUID | None = None,
    ) -> SessionToken:
        return self.sessions.issue(
            self.proof(subject, mfa_level=mfa_level, organization_id=organization_id)
        )


def auth_checks(
    issuance: "Issuance", api: Engine, worker: Engine, issuer: Engine
) -> None:
    sessions = issuance.sessions
    for engine in (api, worker, issuer):
        assert_sql_denial(
            engine,
            "SELECT public.veriq_auth_confirm(NULL, NULL, NULL, NULL, NULL, NULL)",
        )
        assert_sql_denial(engine, "SELECT proof_hash FROM auth_credential_proofs")
    for engine in (api, worker, issuance.verifier.engine):
        assert_sql_denial(
            engine,
            "SELECT public.veriq_auth_issue(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)",
        )
    assert_sql_denial(
        issuer, "SELECT public.veriq_session_issue(NULL, NULL, NULL, NULL, NULL, NULL)"
    )
    assert_sql_denial(api, "SELECT public.veriq_session_revoke(NULL, NULL, NULL, true)")
    for engine in (api, worker, issuer):
        assert_sql_denial(engine, "UPDATE auth_audit_events SET result = 'failed'")
        assert_sql_denial(engine, "DELETE FROM auth_audit_events")
        assert_sql_denial(engine, "DELETE FROM notification_outbox")

    proof = issuance.proof(MULTI)
    denied(lambda: sessions.issue(CredentialProof(proof.id, b"wrong")))
    assert proof.secret.hex() not in repr(proof)
    token = sessions.issue(proof)
    denied(lambda: sessions.issue(proof))
    expired = issuance.proof(MULTI)
    with issuance.owner.begin() as connection:
        connection.execute(
            text("UPDATE auth_credential_proofs SET expires_at = now() WHERE id = :id"),
            {"id": expired.id},
        )
    denied(lambda: sessions.issue(expired))

    stale = issuance.proof(MULTI)
    pending = issuance.proof(MULTI)
    barrier = Barrier(2)

    def redeem() -> SessionToken | None:
        barrier.wait(timeout=10)
        try:
            return sessions.issue(pending)
        except AccessDenied:
            return None

    def revoke_all() -> int:
        barrier.wait(timeout=10)
        return sessions.revoke(token, all_for_account=True)

    with ThreadPoolExecutor(max_workers=2) as executor:
        redeeming = executor.submit(redeem)
        revoking = executor.submit(revoke_all)
        replacement = redeeming.result(timeout=15)
        assert revoking.result(timeout=15) == (1 if replacement is None else 2)
    if replacement is not None:
        denied(lambda: sessions.resolve(replacement))
    denied(lambda: sessions.issue(pending))
    denied(lambda: sessions.issue(stale))
    denied(
        lambda: issuance.verifier.confirm(
            MULTI.user_id, 1, mfa_level=0, organization_id=None
        )
    )
    fresh = sessions.issue(issuance.proof(MULTI))
    assert sessions.resolve(fresh).user_id == MULTI.user_id
    assert sessions.revoke(fresh) == 1

    context = RequestContext.new()
    event_id = uuid4()

    def record_attempt() -> bool:
        with api.begin() as connection:
            return append_attempt(
                connection, event_id, context, AuthEvent.LOGIN, AuthResult.DENIED
            )

    with ThreadPoolExecutor(max_workers=4) as executor:
        assert all(executor.map(lambda _: record_attempt(), range(8)))
    with api.begin() as connection:
        assert not append_attempt(
            connection,
            uuid4(),
            context,
            AuthEvent.SESSIONS_REVOKED,
            AuthResult.SUCCEEDED,
        )
        assert not append_attempt(
            connection, event_id, context, AuthEvent.LOGIN, AuthResult.FAILED
        )

    def claim() -> Notice | None:
        with worker.begin() as connection:
            return claim_notice(connection)

    with ThreadPoolExecutor(max_workers=4) as executor:
        claims = list(executor.map(lambda _: claim(), range(4)))
    claimed = [notice for notice in claims if notice is not None]
    assert len(claimed) == 1
    first = claimed[0]
    with issuance.owner.begin() as connection:
        assert (
            connection.execute(
                text("SELECT count(*) FROM auth_audit_events WHERE id = :id"),
                {"id": event_id},
            ).scalar_one()
            == 1
        )
        connection.execute(
            text(
                "UPDATE notification_outbox SET lease_until = now() WHERE event_id = :id"
            ),
            {"id": first.event_id},
        )
    second = claim()
    assert second is not None and second.event_id == first.event_id
    assert second.claim_id != first.claim_id
    with worker.begin() as connection:
        assert not acknowledge_notice(connection, first)
        assert acknowledge_notice(connection, second)
        assert acknowledge_notice(connection, second)
    assert claim() is None
    print(
        "Auth PostgreSQL: isolated proof issuer, replay/expiry, concurrent revoke, audit and outbox passed."
    )


def main() -> None:
    url = database_url()
    assert url.database is not None and url.database.startswith("memberships_test_")
    owner = create_database_engine()
    issuer = create_database_engine()
    verifier = create_database_engine()

    @event.listens_for(verifier, "begin")
    def assume_fixture_verifier(connection: Connection) -> None:
        connection.exec_driver_sql("SET LOCAL ROLE veriq_credential_verifier")

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
        issuance = Issuance(sessions, CredentialVerifier(verifier), owner)
        auth_checks(issuance, api, worker, issuer)
        assert_sql_denial(api, "SELECT token_hash FROM auth_sessions")
        assert_sql_denial(
            api, "SELECT public.veriq_session_issue(NULL, NULL, NULL, NULL, NULL, NULL)"
        )
        assert_sql_denial(issuer, "SELECT token_hash FROM auth_sessions")
        assert_sql_denial(
            worker, "SELECT public.veriq_session_revoke(NULL, NULL, NULL, false)"
        )
        lifecycle_checks(owner, issuance)
        expiry_checks(owner, issuance, api)
        tenant_checks(owner, issuance)
        concurrency_checks(owner, issuance)
        print(
            "Sessions smoke: hashing, expiry, revoke, rotation, organization MFA, RLS and concurrency passed."
        )
    finally:
        worker.dispose()
        api.dispose()
        verifier.dispose()
        issuer.dispose()
        owner.dispose()


if __name__ == "__main__":
    main()
