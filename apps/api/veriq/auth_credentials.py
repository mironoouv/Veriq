"""Internal capability produced only at the trusted credential verification boundary."""

import secrets
from dataclasses import dataclass, field
from hashlib import sha256
from uuid import UUID, uuid4

from sqlalchemy import Engine, text

from veriq.auth_audit import RequestContext
from veriq.tenant_access import AccessDenied


@dataclass(frozen=True)
class CredentialProof:
    id: UUID
    secret: bytes = field(repr=False)

    @property
    def digest(self) -> bytes:
        return sha256(self.secret).digest()


class CredentialVerifier:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def confirm(
        self,
        user_id: UUID,
        credential_version: int,
        *,
        mfa_level: int,
        organization_id: UUID | None,
    ) -> CredentialProof:
        """Record the result of trusted verification using its observed account version."""
        proof = CredentialProof(uuid4(), secrets.token_bytes(32))
        with self.engine.begin() as connection:
            accepted = connection.execute(
                text("""SELECT public.veriq_auth_confirm(
                    :id, :user, :version, :hash, :org, CAST(:mfa AS smallint)
                )"""),
                {
                    "id": proof.id,
                    "user": user_id,
                    "version": credential_version,
                    "hash": proof.digest,
                    "org": organization_id,
                    "mfa": mfa_level,
                },
            ).scalar_one()
            if not accepted:
                raise AccessDenied
        return proof

    def confirm_password(
        self,
        user_id: UUID,
        credential_version: int,
        *,
        organization_id: UUID | None,
        expected_hash: str,
        replacement: str | None,
        context: RequestContext,
    ) -> CredentialProof:
        """Record verified primary credentials through the password-only SQL role."""
        proof = CredentialProof(uuid4(), secrets.token_bytes(32))
        with self.engine.begin() as connection:
            accepted = connection.execute(
                text(
                    "SELECT public.veriq_password_confirm(:id, :user, :version, :hash, :org, :expected, :replacement, :request, :correlation)"
                ),
                {
                    "id": proof.id,
                    "user": user_id,
                    "version": credential_version,
                    "hash": proof.digest,
                    "org": organization_id,
                    "expected": expected_hash,
                    "replacement": replacement,
                    "request": context.request_id,
                    "correlation": context.correlation_id,
                },
            ).scalar_one()
            if not accepted:
                raise AccessDenied
        return proof
