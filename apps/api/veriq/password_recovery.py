"""Password change and email recovery behind the existing trusted boundaries."""

import os
import unicodedata
from uuid import uuid4

from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.fernet import Fernet
from sqlalchemy import Engine, text

from veriq.auth_audit import AuthEvent, AuthResult, RequestContext, append_attempt
from veriq.registration_policy import HASHER, PasswordPolicy, supported_hash
from veriq.sessions import SessionPolicy, SessionToken
from veriq.tenant_access import AccessDenied
from veriq.verification_mail import VerificationMail


def recovery_enabled() -> bool:
    return (
        os.environ.get("VERIQ_ENV") == "test"
        and os.environ.get("VERIQ_ENABLE_TEST_PASSWORD_RECOVERY") == "1"
    )


class PasswordRecovery:
    def __init__(
        self,
        api: Engine,
        verifier: Engine,
        sessions: SessionPolicy,
        policy: PasswordPolicy,
        cipher: Fernet,
    ) -> None:
        self.api = api
        self.verifier = verifier
        self.sessions = sessions
        self.policy = policy
        self.cipher = cipher

    def change(
        self, token: SessionToken, current: str, new: str, context: RequestContext
    ) -> None:
        gate = token._gate(self.sessions)
        params = {
            "id": gate.session_id,
            "digest": gate.digest,
            "limits": list(gate.limits),
        }
        with self.verifier.connect() as connection:
            row = connection.execute(
                text("""SELECT * FROM public.veriq_password_session_candidate(
                    :id,:digest,CAST(:limits AS interval[])
                )"""),
                params,
            ).one_or_none()
        if row is None or not supported_hash(row.password_hash):
            raise AccessDenied
        original = unicodedata.normalize("NFC", current)
        try:
            HASHER.verify(row.password_hash, original)
        except (InvalidHashError, VerificationError, UnicodeError):
            raise AccessDenied from None
        if original == unicodedata.normalize("NFC", new):
            raise ValueError("Password must change")
        replacement = self.policy.hash(new)
        with self.verifier.begin() as connection:
            accepted = connection.execute(
                text("""SELECT public.veriq_password_change(
                    :id,:digest,CAST(:limits AS interval[]),:version,:expected,:new,:request,:correlation
                )"""),
                {
                    **params,
                    "version": row.credential_version,
                    "expected": row.password_hash,
                    "new": replacement,
                    "request": context.request_id,
                    "correlation": context.correlation_id,
                },
            ).scalar_one()
            if not accepted:
                raise AccessDenied

    def request(self, email: str, context: RequestContext) -> None:
        token = SessionToken.generate()
        gate = token._gate(self.sessions)
        envelope = VerificationMail(email, token.value, "password_reset").seal(
            self.cipher
        )
        with self.api.begin() as connection:
            connection.execute(
                text(
                    "SELECT public.veriq_password_reset_start(:email,:id,:digest,:envelope)"
                ),
                {
                    "email": email,
                    "id": gate.session_id,
                    "digest": gate.digest,
                    "envelope": envelope,
                },
            )
            append_attempt(
                connection,
                uuid4(),
                context,
                AuthEvent.PASSWORD_RESET,
                AuthResult.SUCCEEDED,
            )

    def confirm(
        self, token: SessionToken, email: str, new: str, context: RequestContext
    ) -> None:
        gate = token._gate(self.sessions)
        replacement = self.policy.hash(new)
        with self.api.begin() as connection:
            accepted = connection.execute(
                text(
                    "SELECT public.veriq_password_reset_finish(:id,:digest,:email,:new,:request,:correlation)"
                ),
                {
                    "id": gate.session_id,
                    "digest": gate.digest,
                    "email": email,
                    "new": replacement,
                    "request": context.request_id,
                    "correlation": context.correlation_id,
                },
            ).scalar_one()
            if not accepted:
                append_attempt(
                    connection,
                    uuid4(),
                    context,
                    AuthEvent.PASSWORD_RESET,
                    AuthResult.DENIED,
                )
        if not accepted:
            raise AccessDenied
