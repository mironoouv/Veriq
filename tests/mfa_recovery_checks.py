"""Real PostgreSQL independent MFA recovery, authorization and concurrency."""

import base64
import json
import os
import secrets
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from uuid import UUID, uuid4

from cryptography.fernet import Fernet
from sqlalchemy import Connection, Engine, event, text
from sqlalchemy.exc import DBAPIError
from veriq.auth_audit import RequestContext
from veriq.auth_credentials import CredentialProof, CredentialVerifier
from veriq.database import create_database_engine, database_url
from veriq.mfa import Mfa
from veriq.mfa_crypto import FactorKeys, totp
from veriq.mfa_recovery import MfaRecovery, RecoveryAction
from veriq.password_recovery import PasswordRecovery
from veriq.registration_policy import HASHER, PasswordPolicy
from veriq.sessions import Sessions, SessionToken
from veriq.tenant_access import AccessDenied
from veriq.verification_mail import (
    LocalMailbox,
    deliver_password_notice,
    deliver_verification,
)


def query(engine: Engine, sql: str, **values: Any) -> Any:
    with engine.begin() as conn:
        result = conn.execute(text(sql), values)
        return result.scalar_one() if result.returns_rows else None


def role(name: str) -> Engine:
    engine = create_database_engine()

    @event.listens_for(engine, "begin")
    def assume(connection: Connection) -> None:
        connection.exec_driver_sql(f"SET LOCAL ROLE {name}")

    return engine


def denied(call: Callable[[], object]) -> None:
    try:
        call()
    except AccessDenied:
        return
    raise AssertionError("Expected recovery denial")


def run(
    owner: Engine,
    api: Engine,
    verifier: Engine,
    issuer: Engine,
    mfa: Engine,
    worker: Engine,
    root: Path,
) -> None:
    keys = FactorKeys("fixture", {"fixture": secrets.token_bytes(32)})
    sessions = Sessions(api, issuer=issuer)
    service = MfaRecovery(api, mfa, sessions.policy, keys)
    password = CredentialVerifier(verifier)
    context = RequestContext.new
    stored = HASHER.hash("synthetic independent recovery passphrase")
    account, reviewer, approver, third, outsider = (uuid4() for _ in range(5))
    org, other_org = uuid4(), uuid4()
    source_id = uuid4()
    for user in (account, reviewer, approver, third, outsider):
        query(
            owner,
            "INSERT INTO users(id,email_normalized,email_verified_at,password_hash) VALUES (:id,:mail,now(),:hash)",
            id=user,
            mail=f"{user.hex}@example.invalid",
            hash=stored,
        )
    for tenant in (org, other_org):
        query(
            owner,
            """INSERT INTO organizations (id,slug,display_name,timezone,status)
            VALUES (:id,:slug,'Recovery test','UTC','active')""",
            id=tenant,
            slug=tenant.hex,
        )
    member_ids: dict[UUID, UUID] = {}
    for user, tenant in (
        (account, org),
        (reviewer, org),
        (third, org),
        (outsider, other_org),
    ):
        member_ids[user] = uuid4()
        query(
            owner,
            """INSERT INTO organization_memberships(id,user_id,organization_id,status)
            VALUES (:id,:user,:org,'active')""",
            id=member_ids[user],
            user=user,
            org=tenant,
        )
    role_ids = {org: uuid4(), other_org: uuid4()}
    for tenant, role_id in role_ids.items():
        query(
            owner,
            "INSERT INTO organization_roles VALUES (:org,:id,'org_admin')",
            org=tenant,
            id=role_id,
        )
        query(
            owner,
            "INSERT INTO organization_role_permissions VALUES (:org,:id,'mfa.recovery.verify')",
            org=tenant,
            id=role_id,
        )

    def assign(user: UUID, tenant: UUID) -> None:
        query(
            owner,
            "INSERT INTO membership_roles (organization_id,membership_id,role_id) VALUES (:org,:member,:id)",
            org=tenant,
            member=member_ids[user],
            id=role_ids[tenant],
        )

    for user, tenant in (
        (account, org),
        (reviewer, org),
        (third, org),
        (outsider, other_org),
    ):
        assign(user, tenant)
    platform = query(
        owner, "SELECT id FROM platform_roles WHERE code='mfa_recovery_approver'"
    )
    for user in (approver, reviewer):
        query(
            owner,
            "INSERT INTO platform_role_assignments VALUES (:user,:id)",
            user=user,
            id=platform,
        )

    def version(user: UUID) -> int:
        return int(
            query(owner, "SELECT credential_version FROM users WHERE id=:id", id=user)
        )

    def primary(request: RequestContext | None = None) -> CredentialProof:
        return password.confirm_password(
            account,
            version(account),
            organization_id=None,
            expected_hash=stored,
            replacement=None,
            context=request or context(),
        )

    def staff(
        user: UUID, tenant: UUID | None, case: UUID, release: bool = False
    ) -> SessionToken:
        proof = CredentialVerifier(role_mfa).confirm(
            user, version(user), mfa_level=1, organization_id=tenant
        )
        token = sessions.issue(proof)
        query(
            owner,
            """INSERT INTO mfa_session_assurance(session_id,purpose,verified_at,resource_id)
            VALUES (:id,:purpose,now(),:case)""",
            id=token._gate(sessions.policy).session_id,
            purpose="mfa_recovery_release" if release else "mfa_recovery_review",
            case=case,
        )
        return token

    role_mfa = role("veriq_credential_verifier")
    try:
        Mfa(mfa, sessions, keys).prepare_enrollment(account, context())
        query(
            owner,
            "UPDATE mfa_factors SET confirmed_at=now() WHERE user_id=:id",
            id=account,
        )
        query(
            owner,
            "INSERT INTO mfa_recovery_sources(user_id,organization_id,source_id) VALUES (:id,:org,:source)",
            id=account,
            org=org,
            source=source_id,
        )
        first = context()
        service.start(primary(first), first)
        case = query(
            owner, "SELECT id FROM mfa_recovery_requests WHERE user_id=:id", id=account
        )
        for _ in range(3):
            service.start(primary(), context())
        assert (
            query(
                owner,
                "SELECT count(*) FROM mfa_recovery_requests WHERE user_id=:id",
                id=account,
            )
            == 1
        )
        denied(
            lambda: service.prepare(
                case,
                secrets.token_urlsafe(32),
                secrets.token_urlsafe(32),
                account,
                primary(),
            )
        )

        def apply(
            token: SessionToken, action: RecoveryAction, op: UUID | None = None
        ) -> str | None:
            return service.transition(
                token,
                case,
                action,
                op or uuid4(),
                context(),
                source_id if action is RecoveryAction.VERIFY else None,
            )

        old = staff(account, org, case)
        denied(lambda: apply(old, RecoveryAction.VERIFY))
        denied(lambda: apply(staff(outsider, other_org, case), RecoveryAction.VERIFY))
        denied(lambda: apply(staff(reviewer, org, uuid4()), RecoveryAction.VERIFY))
        operator = staff(reviewer, org, case)
        approved = staff(approver, None, case)
        releaser = staff(approver, None, case, True)
        denied(
            lambda: service.transition(
                operator, case, RecoveryAction.VERIFY, uuid4(), context(), uuid4()
            )
        )
        apply(operator, RecoveryAction.VERIFY)
        denied(lambda: apply(staff(reviewer, None, case), RecoveryAction.APPROVE))
        apply(approved, RecoveryAction.APPROVE)
        assert not deliver_password_notice(worker, LocalMailbox(root / "unavailable"))
        denied(lambda: apply(releaser, RecoveryAction.RELEASE))
        adjudicator = staff(third, org, case)
        apply(adjudicator, RecoveryAction.DISPUTE)
        denied(lambda: apply(releaser, RecoveryAction.RELEASE))
        apply(adjudicator, RecoveryAction.REOPEN)
        denied(
            lambda: service.transition(
                operator, case, RecoveryAction.VERIFY, uuid4(), context(), uuid4()
            )
        )
        apply(operator, RecoveryAction.VERIFY)
        apply(approved, RecoveryAction.APPROVE)

        def receipt() -> None:
            query(
                owner,
                "UPDATE notification_outbox SET lease_until=now() WHERE delivered_at IS NULL",
            )
            while deliver_password_notice(worker, LocalMailbox(root)):
                pass
            query(
                owner,
                """UPDATE notification_outbox SET delivered_at=now()-interval '25 hours'
                WHERE event_id=(SELECT approved_event FROM mfa_recovery_requests WHERE id=:id)
                  AND delivered_at IS NOT NULL""",
                id=case,
            )

        receipt()
        with ThreadPoolExecutor(max_workers=1) as executor:
            with owner.begin() as connection:
                connection.execute(
                    text(
                        "UPDATE organization_memberships SET status='revoked' WHERE id=:id"
                    ),
                    {"id": member_ids[reviewer]},
                )
                releasing = executor.submit(apply, releaser, RecoveryAction.RELEASE)
                try:
                    releasing.result(timeout=0.2)
                except TimeoutError:
                    pass
                else:
                    raise AssertionError("Release did not wait for authority mutation")
            denied(lambda: releasing.result(timeout=10))
        query(
            owner,
            "UPDATE organization_memberships SET status='active' WHERE id=:id",
            id=member_ids[reviewer],
        )
        assign(reviewer, org)
        apply(adjudicator, RecoveryAction.REOPEN)
        operator = staff(reviewer, org, case)
        denied(
            lambda: service.transition(
                operator, case, RecoveryAction.VERIFY, uuid4(), context(), uuid4()
            )
        )
        apply(operator, RecoveryAction.VERIFY)
        apply(approved, RecoveryAction.APPROVE)
        receipt()

        def release(operation: UUID) -> str | None:
            try:
                return apply(releaser, RecoveryAction.RELEASE, operation)
            except AccessDenied:
                return None

        operations = (uuid4(), uuid4())
        with ThreadPoolExecutor(max_workers=2) as executor:
            releases = list(executor.map(release, operations))
        assert sum(value is not None for value in releases) == 1
        capability = next(value for value in releases if value is not None)
        winner = operations[releases.index(capability)]
        assert apply(releaser, RecoveryAction.RELEASE, winner) is None
        assert (
            query(
                owner,
                "SELECT count(*) FROM mfa_recovery_enrollments WHERE request_id=:id",
                id=case,
            )
            == 1
        )
        assert (
            query(
                owner, "SELECT count(*) FROM mfa_factors WHERE user_id=:id", id=account
            )
            == 0
        )
        denied(lambda: sessions.resolve(old))
        denied(lambda: sessions.issue(primary()))
        nonce = secrets.token_urlsafe(32)
        query(
            owner,
            "UPDATE mfa_recovery_enrollments SET expires_at=now() WHERE request_id=:id",
            id=case,
        )
        denied(lambda: service.prepare(case, capability, nonce, account, primary()))
        assert (
            query(
                owner,
                "SELECT count(*) FROM mfa_recovery_holds WHERE user_id=:id",
                id=account,
            )
            == 1
        )
        blocklist = root / "blocklist"
        blocklist.write_text(
            sha256(b"synthetic blocked passphrase").hexdigest(), encoding="ascii"
        )
        cipher = Fernet(Fernet.generate_key())
        recovery = PasswordRecovery(
            api, verifier, sessions.policy, PasswordPolicy(blocklist), cipher
        )
        mail = f"{account.hex}@example.invalid"
        recovery.request(mail, context())
        assert deliver_verification(worker, cipher, LocalMailbox(root))
        reset_id = query(
            owner, "SELECT id FROM password_reset_proofs WHERE user_id=:id", id=account
        )
        document = json.loads((root / f"{reset_id}.json").read_text(encoding="utf-8"))
        reset = SessionToken(document["path"].split("#")[1])
        recovery.confirm(
            reset, mail, "synthetic replacement recovery password", context()
        )
        assert (
            query(
                owner,
                "SELECT count(*) FROM mfa_recovery_holds WHERE user_id=:id",
                id=account,
            )
            == 1
        )
        stored = query(
            owner, "SELECT password_hash FROM users WHERE id=:id", id=account
        )
        denied(lambda: sessions.issue(primary()))
        next_case = uuid4()
        apply(adjudicator, RecoveryAction.REOPEN, next_case)
        case = next_case
        operator = staff(reviewer, org, case)
        approved = staff(approver, None, case)
        releaser = staff(approver, None, case, True)
        denied(
            lambda: service.transition(
                operator, case, RecoveryAction.VERIFY, uuid4(), context(), uuid4()
            )
        )
        apply(operator, RecoveryAction.VERIFY)
        apply(approved, RecoveryAction.APPROVE)
        receipt()
        replacement_capability = apply(releaser, RecoveryAction.RELEASE)
        assert replacement_capability is not None
        capability = replacement_capability
        seed = base64.b32decode(
            service.prepare(case, capability, nonce, account, primary())
        )
        counter = query(
            owner, "SELECT floor(extract(epoch FROM clock_timestamp())/30)::bigint"
        )
        code = totp(seed, counter)
        denied(
            lambda: service.complete(
                case, capability, secrets.token_urlsafe(32), code, context()
            )
        )
        denied(lambda: service.complete(case, capability, nonce, "invalid", context()))
        assert (
            query(
                owner,
                "SELECT attempts FROM mfa_recovery_enrollments WHERE request_id=:id",
                id=case,
            )
            == 1
        )
        assert len(service.complete(case, capability, nonce, code, context())) == 10
        denied(lambda: service.complete(case, capability, nonce, code, context()))
        assert (
            query(
                owner, "SELECT state FROM mfa_recovery_requests WHERE id=:id", id=case
            )
            == "completed"
        )
        assert (
            query(
                owner,
                "SELECT count(*) FROM auth_sessions WHERE user_id=:id AND revoked_at IS NULL",
                id=account,
            )
            == 0
        )
        assert (
            query(
                owner,
                "SELECT count(*) FROM mfa_factors WHERE user_id=:id AND confirmed_at IS NOT NULL",
                id=account,
            )
            == 1
        )
        assert (
            query(
                owner,
                "SELECT count(*) FROM mfa_recovery_holds WHERE user_id=:id",
                id=account,
            )
            == 0
        )
        try:
            query(api, "SELECT count(*) FROM mfa_recovery_requests")
        except DBAPIError as error:
            assert getattr(error.orig, "sqlstate", None) == "42501"
        else:
            raise AssertionError("API acquired direct recovery table access")
        print(
            "Independent MFA recovery: staff separation, revoked membership race, dispute, release race, expiry/replay, hold and no session passed."
        )
    finally:
        role_mfa.dispose()


def main() -> None:
    url = database_url()
    assert url.database is not None and url.database.startswith("memberships_test_")
    owner = create_database_engine()
    api = create_database_engine(
        url.set(username="veriq_api", password=os.environ["VERIQ_API_DB_PASSWORD"])
    )
    worker = create_database_engine(
        url.set(
            username="veriq_worker", password=os.environ["VERIQ_WORKER_DB_PASSWORD"]
        )
    )
    verifier, issuer, mfa = (
        role(name)
        for name in (
            "veriq_password_verifier",
            "veriq_session_issuer",
            "veriq_mfa_verifier",
        )
    )
    try:
        with TemporaryDirectory() as directory:
            run(owner, api, verifier, issuer, mfa, worker, Path(directory))
    finally:
        for engine in (owner, api, worker, verifier, issuer, mfa):
            engine.dispose()


if __name__ == "__main__":
    main()
