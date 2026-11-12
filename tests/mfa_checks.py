"""Real PostgreSQL MFA policy, replay, one-use challenges and session freshness."""

import base64
import os
import secrets
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Connection, Engine, create_engine, event, text
from sqlalchemy.exc import DBAPIError
from veriq.auth_audit import RequestContext
from veriq.auth_credentials import CredentialVerifier
from veriq.database import create_database_engine, database_url
from veriq.mfa import Mfa, MfaCompletion, Purpose
from veriq.mfa_crypto import FactorKeys, totp
from veriq.registration_policy import HASHER
from veriq.sessions import MfaRequired, Sessions, SessionToken
from veriq.tenant_access import AccessDenied


def query(engine: Engine, statement: str, **values: Any) -> Any:
    with engine.begin() as connection:
        result = connection.execute(text(statement), values)
        return result.scalar_one() if result.returns_rows else None


def role_engine(role: str) -> Engine:
    engine = create_database_engine()

    @event.listens_for(engine, "begin")
    def assume_role(connection: Connection) -> None:
        # Fixed fixture role names in the isolated database.
        connection.exec_driver_sql(f"SET LOCAL ROLE {role}")

    return engine


def denied(call: Callable[[], object], error: type[Exception] = AccessDenied) -> None:
    try:
        call()
    except error:
        return
    raise AssertionError("Expected MFA access denial")


def compete(*calls: Callable[[], MfaCompletion]) -> MfaCompletion:
    barrier = Barrier(len(calls))

    def perform(call: Callable[[], MfaCompletion]) -> MfaCompletion | None:
        barrier.wait(timeout=10)
        try:
            return call()
        except AccessDenied:
            return None

    with ThreadPoolExecutor(max_workers=len(calls)) as executor:
        results = [
            result for result in executor.map(perform, calls) if result is not None
        ]
    assert len(results) == 1
    return results[0]


def checks(
    owner: Engine, api: Engine, verifier: Engine, issuer: Engine, mfa_db: Engine
) -> None:
    sessions = Sessions(api, issuer=issuer)
    password = CredentialVerifier(verifier)
    initial_key = secrets.token_bytes(32)
    service = Mfa(mfa_db, sessions, FactorKeys("old", {"old": initial_key}))
    user = uuid4()
    scope_a, scope_b = uuid4(), uuid4()
    stored = HASHER.hash("synthetic MFA test password")
    query(
        owner,
        """INSERT INTO users (id,email_normalized,email_verified_at,password_hash)
        VALUES (:id,:email,now(),:hash)""",
        id=user,
        email=f"{user.hex}@example.invalid",
        hash=stored,
    )
    for org in (scope_a, scope_b):
        query(
            owner,
            """INSERT INTO organizations (id,slug,display_name,timezone,status)
            VALUES (:id,:slug,'MFA test','UTC','active')""",
            id=org,
            slug=org.hex,
        )
        query(
            owner,
            """INSERT INTO organization_memberships (id, organization_id, user_id, status)
            VALUES (:id,:org,:user,'active')""",
            id=uuid4(),
            org=org,
            user=user,
        )
    query(
        owner, "INSERT INTO organization_mfa_policies VALUES (:org,true,1)", org=scope_b
    )

    def primary(scope: UUID | None) -> SessionToken:
        version = query(
            owner, "SELECT credential_version FROM users WHERE id=:id", id=user
        )
        context = RequestContext.new()
        proof = password.confirm_password(
            user,
            version,
            organization_id=scope,
            expected_hash=stored,
            replacement=None,
            context=context,
        )
        return sessions.issue(proof, context=context, browser=True)

    def challenge(scope: UUID | None) -> SessionToken:
        version = query(
            owner, "SELECT credential_version FROM users WHERE id=:id", id=user
        )
        proof = password.confirm_password(
            user,
            version,
            organization_id=scope,
            expected_hash=stored,
            replacement=None,
            context=RequestContext.new(),
        )
        result = service.begin_login(proof)
        assert result is not None
        denied(lambda: sessions.issue(proof, browser=True))
        return result

    student_role = uuid4()
    query(
        owner,
        "INSERT INTO organization_roles VALUES (:org,:id,'student')",
        org=scope_a,
        id=student_role,
    )
    query(
        owner,
        """INSERT INTO membership_roles (organization_id,membership_id,role_id)
        SELECT :org,id,:role FROM organization_memberships WHERE user_id=:user AND organization_id=:org""",
        org=scope_a,
        user=user,
        role=student_role,
    )
    a = primary(scope_a)
    denied(lambda: primary(scope_b), MfaRequired)
    denied(lambda: sessions.rotate(a, organization_id=scope_b))
    for role in ("org_admin", "technician"):
        role_id = uuid4()
        query(
            owner,
            "INSERT INTO organization_roles VALUES (:org,:id,:code)",
            org=scope_a,
            id=role_id,
            code=role,
        )
        query(
            owner,
            """INSERT INTO membership_roles (organization_id,membership_id,role_id)
            SELECT :org,id,:role FROM organization_memberships WHERE user_id=:user AND organization_id=:org""",
            org=scope_a,
            user=user,
            role=role_id,
        )
        denied(lambda: primary(scope_a), MfaRequired)
        query(
            owner,
            "DELETE FROM membership_roles WHERE organization_id=:org AND role_id=:id",
            org=scope_a,
            id=role_id,
        )
    query(
        owner,
        """INSERT INTO platform_role_assignments SELECT :user,id FROM platform_roles WHERE code='superadmin'""",
        user=user,
    )
    denied(lambda: primary(None), MfaRequired)
    query(owner, "DELETE FROM platform_role_assignments WHERE user_id=:user", user=user)

    seed = base64.b32decode(service.prepare_enrollment(user, RequestContext.new()))
    denied(lambda: service.prepare_enrollment(user, RequestContext.new()))
    rotated_keys = FactorKeys(
        "new", {"old": initial_key, "new": secrets.token_bytes(32)}
    )
    service = Mfa(mfa_db, sessions, rotated_keys)
    encrypted = query(
        owner, "SELECT ciphertext FROM mfa_factors WHERE user_id=:user", user=user
    )
    assert seed not in encrypted

    def counter() -> int:
        return int(
            query(
                owner, "SELECT floor(extract(epoch FROM clock_timestamp())/30)::bigint"
            )
        )

    def finish(
        token: SessionToken,
        code: str,
        *,
        recovery: bool = False,
        current: SessionToken | None = None,
    ) -> MfaCompletion:
        return service.finish(
            token,
            code,
            recovery=recovery,
            current=current,
            context=RequestContext.new(),
        )

    expired = challenge(scope_b)
    query(
        owner,
        "UPDATE mfa_challenges SET expires_at=now() WHERE id=:id",
        id=expired._gate(sessions.policy).session_id,
    )
    denied(lambda: finish(expired, totp(seed, counter())))
    pending = challenge(scope_b)
    denied(lambda: sessions.resolve(pending))
    denied(lambda: finish(pending, "invalid"))
    denied(lambda: finish(pending, totp(seed, counter() - 3)))
    enrollment_counter = counter() - 1
    enrolled = finish(pending, totp(seed, enrollment_counter))
    assert len(enrolled.recovery_codes) == 10
    assert sessions.resolve(enrolled.token).organization_id == scope_b
    assert (
        query(owner, "SELECT key_id FROM mfa_factors WHERE user_id=:user", user=user)
        == "new"
    )
    denied(lambda: sessions.resolve(a))
    denied(lambda: finish(pending, totp(seed, enrollment_counter)))
    replay = challenge(scope_b)
    denied(lambda: finish(replay, totp(seed, enrollment_counter)))

    first, second = challenge(scope_b), challenge(scope_b)
    shared = enrolled.recovery_codes[0]
    won = compete(
        lambda: finish(first, shared, recovery=True),
        lambda: finish(second, shared, recovery=True),
    )
    assert sessions.resolve(won.token).mfa_level == 1
    assert (
        query(
            owner, "SELECT count(*) FROM mfa_recovery_codes WHERE used_at IS NOT NULL"
        )
        == 1
    )
    once = challenge(scope_b)
    compete(
        lambda: finish(once, enrolled.recovery_codes[1], recovery=True),
        lambda: finish(once, enrolled.recovery_codes[2], recovery=True),
    )
    assert (
        query(
            owner, "SELECT count(*) FROM mfa_recovery_codes WHERE used_at IS NOT NULL"
        )
        == 2
    )
    assert (
        query(
            owner,
            "SELECT count(*) FROM mfa_recovery_codes WHERE digest=convert_to(:code,'UTF8')",
            code=shared,
        )
        == 0
    )

    current = won.token
    step = service.begin_step_up(current, Purpose.SENSITIVE)
    before = query(
        owner,
        "SELECT absolute_expires_at FROM auth_sessions WHERE id=:id",
        id=current._gate(sessions.policy).session_id,
    )
    denied(
        lambda: finish(step, enrolled.recovery_codes[3], recovery=True, current=current)
    )
    elevated = finish(step, totp(seed, counter()), current=current).token
    denied(lambda: sessions.resolve(current))
    denied(lambda: finish(step, totp(seed, counter()), current=elevated))
    assert (
        query(
            owner,
            "SELECT absolute_expires_at FROM auth_sessions WHERE id=:id",
            id=elevated._gate(sessions.policy).session_id,
        )
        == before
    )
    with api.begin() as connection:
        service.require_fresh(connection, elevated, Purpose.SENSITIVE)
        denied(
            lambda: service.require_fresh(connection, elevated, Purpose.FACTOR_DISABLE)
        )
    query(
        owner, "UPDATE mfa_session_assurance SET verified_at=now()-interval '6 minutes'"
    )
    assert sessions.resolve(elevated).user_id == user
    with api.begin() as connection:
        denied(lambda: service.require_fresh(connection, elevated, Purpose.SENSITIVE))
    switched = sessions.rotate(elevated, organization_id=scope_a)
    assert sessions.resolve(switched).organization_id == scope_a
    with api.begin() as connection:
        denied(lambda: service.require_fresh(connection, switched, Purpose.SENSITIVE))
    assert (
        sessions.resolve(
            sessions.rotate(switched, organization_id=scope_b)
        ).organization_id
        == scope_b
    )
    assert not query(
        mfa_db,
        "SELECT public.veriq_mfa_can_disable(:user, CAST(:limits AS interval[]))",
        user=user,
        limits=list(sessions.policy.limits),
    )

    for statement in (
        "SELECT ciphertext FROM mfa_factors",
        "SELECT digest FROM mfa_recovery_codes",
        "SELECT * FROM organization_mfa_policies",
    ):
        try:
            query(api, statement)
        except DBAPIError as error:
            assert getattr(error.orig, "sqlstate", None) == "42501"
        else:
            raise AssertionError("Runtime unexpectedly read MFA storage")
    assert (
        query(
            owner,
            """SELECT count(*) FROM auth_audit_events WHERE target_id=:user
                         AND event_type='mfa_attempt' AND result='succeeded'""",
            user=user,
        )
        >= 4
    )
    assert (
        query(
            owner,
            "SELECT count(*) FROM notification_outbox n JOIN auth_audit_events e ON e.id=n.event_id WHERE e.target_id=:user",
            user=user,
        )
        == 0
    )
    print(
        "MFA PostgreSQL: RFC6238 enrollment, replay/expiry, concurrent challenges and codes, role policy, rotation and scoped step-up passed."
    )


def main() -> None:
    url = database_url()
    assert url.database is not None and url.database.startswith("memberships_test_")
    owner = create_database_engine()
    api = create_engine(
        url.set(username="veriq_api", password=os.environ["VERIQ_API_DB_PASSWORD"]),
        hide_parameters=True,
    )
    verifier = role_engine("veriq_password_verifier")
    issuer = role_engine("veriq_browser_issuer")
    mfa_db = role_engine("veriq_mfa_verifier")
    try:
        checks(owner, api, verifier, issuer, mfa_db)
    finally:
        for engine in (owner, api, verifier, issuer, mfa_db):
            engine.dispose()


if __name__ == "__main__":
    main()
