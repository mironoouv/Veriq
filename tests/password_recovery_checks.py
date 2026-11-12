"""PostgreSQL race and recovery checks using restricted runtime roles."""

import base64
import json
import os
import secrets
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Barrier
from typing import Any
from uuid import UUID, uuid4

from cryptography.fernet import Fernet
from sqlalchemy import Connection, Engine, event, text
from veriq.auth_audit import RequestContext
from veriq.auth_credentials import CredentialProof, CredentialVerifier
from veriq.database import create_database_engine, database_url
from veriq.mfa import Mfa, Purpose
from veriq.mfa_crypto import FactorKeys, totp
from veriq.password_recovery import PasswordRecovery
from veriq.registration_policy import HASHER, PasswordPolicy
from veriq.sessions import MfaRequired, Sessions, SessionToken
from veriq.tenant_access import AccessDenied
from veriq.verification_mail import (
    LocalMailbox,
    deliver_password_notice,
    deliver_verification,
)

ORIGINAL = "synthetic original credential"
CHANGED = "synthetic changed credential"
RESET = "synthetic reset credential"


def query(engine: Engine, statement: str, **values: Any) -> Any:
    with engine.begin() as connection:
        result = connection.execute(text(statement), values)
        return result.scalar_one() if result.returns_rows else None


def role_engine(role: str) -> Engine:
    engine = create_database_engine()

    @event.listens_for(engine, "begin")
    def assume_role(connection: Connection) -> None:
        connection.exec_driver_sql(f"SET LOCAL ROLE {role}")

    return engine


def denied(
    operation: Callable[[], object], error: type[Exception] = AccessDenied
) -> None:
    try:
        operation()
    except error:
        return
    raise AssertionError("Expected password recovery denial")


class Fixtures:
    def __init__(
        self,
        owner: Engine,
        api: Engine,
        verifier: Engine,
        issuer: Engine,
        worker: Engine,
        root: Path,
    ) -> None:
        self.owner = owner
        self.worker = worker
        self.sessions = Sessions(api, issuer=issuer)
        self.verifier = CredentialVerifier(verifier)
        blocklist = root / "blocklist"
        blocklist.write_text(
            sha256(b"synthetic blocked password").hexdigest(), encoding="ascii"
        )
        self.cipher = Fernet(Fernet.generate_key())
        self.recovery = PasswordRecovery(
            api, verifier, self.sessions.policy, PasswordPolicy(blocklist), self.cipher
        )
        self.root = root

    def account(self) -> tuple[UUID, str]:
        account = uuid4()
        email = f"{account.hex}@example.invalid"
        query(
            self.owner,
            """INSERT INTO users (id,email_normalized,email_verified_at,password_hash)
            VALUES (:id,:email,now(),:hash)""",
            id=account,
            email=email,
            hash=HASHER.hash(ORIGINAL),
        )
        return account, email

    def proof(self, user: UUID) -> CredentialProof:
        stored = query(
            self.owner, "SELECT password_hash FROM users WHERE id=:id", id=user
        )
        version = query(
            self.owner, "SELECT credential_version FROM users WHERE id=:id", id=user
        )
        return self.verifier.confirm_password(
            user,
            version,
            organization_id=None,
            expected_hash=stored,
            replacement=None,
            context=RequestContext.new(),
        )

    def change(self, token: SessionToken, old: str, new: str) -> None:
        self.recovery.change(token, old, new, RequestContext.new())

    def reset_request(self, email: str) -> None:
        self.recovery.request(email, RequestContext.new())

    def reset_token(self, user: UUID) -> SessionToken:
        ident = query(
            self.owner,
            "SELECT id FROM password_reset_proofs WHERE user_id=:id",
            id=user,
        )
        document = json.loads((self.root / f"{ident}.json").read_text(encoding="utf-8"))
        path, proof = document["path"].split("#")
        assert path == "/api/v1/auth/password-reset/confirm"
        return SessionToken(proof)

    def reset_confirm(self, token: SessionToken, email: str, new: str) -> None:
        self.recovery.confirm(token, email, new, RequestContext.new())


def password_change_checks(f: Fixtures) -> None:
    user, _ = f.account()
    current = f.sessions.issue(f.proof(user), browser=True)
    denied(lambda: f.change(current, RESET, CHANGED))
    denied(lambda: f.change(current, ORIGINAL, ORIGINAL), ValueError)
    pending = f.proof(user)
    barrier = Barrier(2)

    def change() -> None:
        barrier.wait(timeout=10)
        f.change(current, ORIGINAL, CHANGED)

    def issue() -> SessionToken | None:
        barrier.wait(timeout=10)
        try:
            return f.sessions.issue(pending, browser=True)
        except AccessDenied:
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        changing = executor.submit(change)
        issuing = executor.submit(issue)
        changing.result(timeout=15)
        issued = issuing.result(timeout=15)
    denied(lambda: f.sessions.resolve(current))
    denied(lambda: f.sessions.issue(pending, browser=True))
    if issued is not None:
        denied(lambda: f.sessions.resolve(issued))
    assert (
        query(f.owner, "SELECT credential_version FROM users WHERE id=:id", id=user)
        == 2
    )
    assert HASHER.verify(
        query(f.owner, "SELECT password_hash FROM users WHERE id=:id", id=user), CHANGED
    )
    assert (
        query(
            f.owner,
            "SELECT count(*) FROM auth_audit_events WHERE target_id=:id AND event_type='password_changed'",
            id=user,
        )
        == 1
    )


def reset_checks(f: Fixtures) -> None:
    user, email = f.account()
    session = f.sessions.issue(f.proof(user), browser=True)
    stale = f.proof(user)
    f.reset_request("unknown-password-reset@example.invalid")
    assert query(f.owner, "SELECT count(*) FROM password_reset_proofs") == 0
    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(f.reset_request, [email] * 8))
    ident = query(
        f.owner, "SELECT id FROM password_reset_proofs WHERE user_id=:id", id=user
    )
    expires = query(
        f.owner,
        "SELECT expires_at FROM password_reset_proofs WHERE user_id=:id",
        id=user,
    )
    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(f.reset_request, [email] * 16))
    assert (
        query(
            f.owner, "SELECT id FROM password_reset_proofs WHERE user_id=:id", id=user
        )
        == ident
    )
    assert (
        query(
            f.owner,
            "SELECT expires_at FROM password_reset_proofs WHERE user_id=:id",
            id=user,
        )
        == expires
    )
    assert (
        query(
            f.owner,
            "SELECT count(*) FROM email_verification_outbox WHERE reset_id=:id",
            id=ident,
        )
        == 1
    )
    assert not deliver_verification(
        f.worker, f.cipher, LocalMailbox(f.root / "unavailable")
    )
    assert query(
        f.owner,
        "SELECT available_at>now() FROM email_verification_outbox WHERE reset_id=:id",
        id=ident,
    )
    query(
        f.owner,
        "UPDATE email_verification_outbox SET available_at=now() WHERE reset_id=:id",
        id=ident,
    )
    ciphertext = query(
        f.owner,
        "SELECT envelope FROM email_verification_outbox WHERE reset_id=:id",
        id=ident,
    )
    assert deliver_verification(f.worker, f.cipher, LocalMailbox(f.root))
    expired = f.reset_token(user)
    assert expired.value.encode() not in ciphertext and email.encode() not in ciphertext
    denied(lambda: f.sessions.resolve(expired))
    denied(lambda: f.reset_confirm(expired, "other@example.invalid", RESET))
    query(
        f.owner,
        "UPDATE password_reset_proofs SET expires_at=now() WHERE user_id=:id",
        id=user,
    )
    denied(lambda: f.reset_confirm(expired, email, RESET))

    f.reset_request(email)
    assert deliver_verification(f.worker, f.cipher, LocalMailbox(f.root))
    proof = f.reset_token(user)
    assert proof.value != expired.value
    barrier = Barrier(2)

    def confirm(_: int) -> bool:
        barrier.wait(timeout=10)
        try:
            f.reset_confirm(proof, email, RESET)
            return True
        except AccessDenied:
            return False

    with ThreadPoolExecutor(max_workers=2) as executor:
        assert sorted(executor.map(confirm, range(2))) == [False, True]
    denied(lambda: f.reset_confirm(proof, email, CHANGED))
    denied(lambda: f.sessions.resolve(session))
    denied(lambda: f.sessions.issue(stale, browser=True))
    assert (
        query(f.owner, "SELECT credential_version FROM users WHERE id=:id", id=user)
        == 2
    )
    assert (
        query(
            f.owner,
            "SELECT count(*) FROM auth_sessions WHERE user_id=:id AND revoked_at IS NULL",
            id=user,
        )
        == 0
    )
    assert (
        query(
            f.owner,
            "SELECT count(*) FROM auth_audit_events WHERE target_id=:id AND event_type='password_reset'",
            id=user,
        )
        == 1
    )


def mfa_checks(f: Fixtures, mfa_engine: Engine) -> None:
    user, email = f.account()
    query(
        f.owner,
        """INSERT INTO platform_role_assignments SELECT :id,id FROM platform_roles WHERE code='superadmin'""",
        id=user,
    )
    service = Mfa(
        mfa_engine, f.sessions, FactorKeys("test", {"test": secrets.token_bytes(32)})
    )
    seed = base64.b32decode(service.prepare_enrollment(user, RequestContext.new()))

    def counter() -> int:
        return int(
            query(
                f.owner,
                "SELECT floor(extract(epoch FROM clock_timestamp())/30)::bigint",
            )
        )

    pending = service.begin_login(f.proof(user))
    assert pending is not None
    enrollment = service.finish(
        pending,
        totp(seed, counter() - 1),
        recovery=False,
        current=None,
        context=RequestContext.new(),
    )
    denied(lambda: f.change(enrollment.token, ORIGINAL, CHANGED))
    challenge = service.begin_step_up(enrollment.token, Purpose.PASSWORD_CHANGE)
    elevated = service.finish(
        challenge,
        totp(seed, counter()),
        recovery=False,
        current=enrollment.token,
        context=RequestContext.new(),
    ).token
    session_id = elevated._gate(f.sessions.policy).session_id
    query(
        f.owner,
        "UPDATE mfa_session_assurance SET verified_at=now()-interval '6 minutes' WHERE session_id=:id",
        id=session_id,
    )
    denied(lambda: f.change(elevated, ORIGINAL, CHANGED))
    query(
        f.owner,
        "UPDATE mfa_session_assurance SET verified_at=now() WHERE session_id=:id",
        id=session_id,
    )
    f.change(elevated, ORIGINAL, CHANGED)
    denied(lambda: f.sessions.resolve(elevated))
    original_factor = query(
        f.owner, "SELECT ciphertext FROM mfa_factors WHERE user_id=:id", id=user
    )
    f.reset_request(email)
    assert deliver_verification(f.worker, f.cipher, LocalMailbox(f.root))
    f.reset_confirm(f.reset_token(user), email, RESET)
    assert (
        query(f.owner, "SELECT ciphertext FROM mfa_factors WHERE user_id=:id", id=user)
        == original_factor
    )
    assert (
        query(
            f.owner,
            "SELECT count(*) FROM auth_sessions WHERE user_id=:id AND revoked_at IS NULL",
            id=user,
        )
        == 0
    )
    denied(lambda: f.sessions.issue(f.proof(user), browser=True), MfaRequired)
    assert service.begin_login(f.proof(user)) is not None


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
    verifier = role_engine("veriq_password_verifier")
    issuer = role_engine("veriq_browser_issuer")
    mfa = role_engine("veriq_mfa_verifier")
    try:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = Fixtures(owner, api, verifier, issuer, worker, root)
            password_change_checks(fixture)
            reset_checks(fixture)
            mfa_checks(fixture, mfa)
            notices = 0
            while deliver_password_notice(worker, LocalMailbox(root)):
                notices += 1
            assert notices == 4
            for path in root.glob("*.json"):
                payload = json.loads(path.read_text(encoding="utf-8"))
                if "event" in payload:
                    assert set(payload) == {"event", "recipient"}
            print(
                "Password PostgreSQL: change/issue race, reset race and expiry, resend stability, mail retry and preserved MFA passed."
            )
    finally:
        for engine in (owner, api, worker, verifier, issuer, mfa):
            engine.dispose()


if __name__ == "__main__":
    main()
