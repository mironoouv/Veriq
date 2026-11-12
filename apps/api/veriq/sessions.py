"""Internal session lifecycle. Call issue only after trusted authentication."""

import os
import re
import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import timedelta
from enum import IntEnum
from hashlib import sha256
from uuid import UUID, uuid4

from sqlalchemy import Connection, Engine, text

from veriq.auth_audit import RequestContext
from veriq.auth_credentials import CredentialProof
from veriq.permissions import SessionGate
from veriq.tenant_access import (
    AccessDenied,
    TenantAccess,
    VerifiedSubject,
    _open_tenant_access,
)

TOKEN_PATTERN = re.compile(r"[0-9a-f]{32}\.[A-Za-z0-9_-]{43}")


class MfaLevel(IntEnum):
    PRIMARY = 0
    VERIFIED = 1


@dataclass(frozen=True)
class SessionPolicy:
    privileged_idle: timedelta = timedelta(minutes=30)
    privileged_absolute: timedelta = timedelta(hours=8)
    ordinary_idle: timedelta = timedelta(hours=2)
    ordinary_absolute: timedelta = timedelta(hours=12)

    def __post_init__(self) -> None:
        for idle, absolute in (
            (self.privileged_idle, self.privileged_absolute),
            (self.ordinary_idle, self.ordinary_absolute),
        ):
            if not timedelta(0) < idle <= absolute:
                raise ValueError("Session lifetimes require 0 < idle <= absolute")

    @classmethod
    def from_environment(cls) -> "SessionPolicy":
        defaults = cls()

        def seconds(name: str, default: timedelta) -> timedelta:
            value = os.environ.get(f"VERIQ_SESSION_{name}_SECONDS")
            return default if value is None else timedelta(seconds=int(value))

        return cls(
            privileged_idle=seconds("PRIVILEGED_IDLE", defaults.privileged_idle),
            privileged_absolute=seconds(
                "PRIVILEGED_ABSOLUTE", defaults.privileged_absolute
            ),
            ordinary_idle=seconds("ORDINARY_IDLE", defaults.ordinary_idle),
            ordinary_absolute=seconds("ORDINARY_ABSOLUTE", defaults.ordinary_absolute),
        )

    @property
    def limits(self) -> tuple[timedelta, timedelta, timedelta, timedelta]:
        return (
            self.privileged_idle,
            self.privileged_absolute,
            self.ordinary_idle,
            self.ordinary_absolute,
        )


@dataclass(frozen=True)
class SessionToken:
    value: str = field(repr=False)

    @classmethod
    def generate(cls) -> "SessionToken":
        return cls(f"{uuid4().hex}.{secrets.token_urlsafe(32)}")

    def _gate(self, policy: SessionPolicy) -> SessionGate:
        if TOKEN_PATTERN.fullmatch(self.value) is None:
            raise AccessDenied
        return SessionGate(
            UUID(hex=self.value[:32]),
            sha256(self.value.encode("ascii")).digest(),
            policy.limits,
        )


@dataclass(frozen=True)
class SessionIdentity:
    user_id: UUID
    organization_id: UUID | None
    mfa_level: MfaLevel


class Sessions:
    def __init__(
        self,
        engine: Engine,
        policy: SessionPolicy | None = None,
        *,
        issuer: Engine | None = None,
    ) -> None:
        self.engine = engine
        self.issuer = issuer
        self.policy = policy if policy is not None else SessionPolicy.from_environment()

    @contextmanager
    def _transaction(self, engine: Engine | None = None) -> Iterator[Connection]:
        with (self.engine if engine is None else engine).connect() as connection:
            connection.execution_options(isolation_level="READ COMMITTED")
            with connection.begin():
                yield connection

    def issue(
        self, proof: CredentialProof, *, context: RequestContext | None = None
    ) -> SessionToken:
        """Redeem a short-lived proof produced by the trusted verifier."""
        if self.issuer is None:
            raise AccessDenied
        token = SessionToken.generate()
        gate = token._gate(self.policy)
        context = context or RequestContext.new()
        with self._transaction(self.issuer) as connection:
            accepted = connection.execute(
                text("""
                    SELECT public.veriq_auth_issue(
                        :proof, :proof_hash, :id, :digest, CAST(:limits AS interval[]),
                        :event, :request, :correlation
                    )
                """),
                {
                    "id": gate.session_id,
                    "proof": proof.id,
                    "proof_hash": proof.digest,
                    "event": uuid4(),
                    "request": context.request_id,
                    "correlation": context.correlation_id,
                    "digest": gate.digest,
                    "limits": list(gate.limits),
                },
            ).scalar_one()
            if not accepted:
                raise AccessDenied
        return token

    def resolve(self, token: SessionToken) -> SessionIdentity:
        gate = token._gate(self.policy)
        with self._transaction() as connection:
            return self._use(connection, gate)

    def rotate(
        self, token: SessionToken, *, organization_id: UUID | None
    ) -> SessionToken:
        """Rotate after selecting a tenant, including reselecting the same tenant or clearing it."""
        previous = token._gate(self.policy)
        replacement = SessionToken.generate()
        with self._transaction() as connection:
            self._use(
                connection, previous, replacement._gate(self.policy), organization_id
            )
        return replacement

    def revoke(
        self,
        token: SessionToken,
        *,
        all_for_account: bool = False,
        context: RequestContext | None = None,
    ) -> int:
        gate = token._gate(self.policy)
        context = context or RequestContext.new()
        with self._transaction() as connection:
            count: int = connection.execute(
                text("""
                    SELECT public.veriq_auth_revoke(
                        :id, :digest, CAST(:limits AS interval[]), :all, :event, :request, :correlation
                    )
                """),
                {
                    "id": gate.session_id,
                    "digest": gate.digest,
                    "limits": list(gate.limits),
                    "all": all_for_account,
                    "event": uuid4(),
                    "request": context.request_id,
                    "correlation": context.correlation_id,
                },
            ).scalar_one()
        return count

    @contextmanager
    def tenant(self, token: SessionToken) -> Iterator[TenantAccess]:
        """Authorize only the tenant selected on the authenticated session."""
        gate = token._gate(self.policy)
        with self._transaction() as connection:
            identity = self._use(connection, gate)
            if identity.organization_id is None:
                raise AccessDenied
            yield _open_tenant_access(
                connection,
                VerifiedSubject(identity.user_id),
                identity.organization_id,
                gate,
            )

    @staticmethod
    def _use(
        connection: Connection,
        gate: SessionGate,
        replacement: SessionGate | None = None,
        target: UUID | None = None,
    ) -> SessionIdentity:
        row = connection.execute(
            text("""
                SELECT * FROM public.veriq_session_use(
                    :id, :digest, CAST(:limits AS interval[]), :next_id, :next_digest, :target
                )
            """),
            {
                "id": gate.session_id,
                "digest": gate.digest,
                "limits": list(gate.limits),
                "next_id": replacement.session_id if replacement else None,
                "next_digest": replacement.digest if replacement else None,
                "target": target,
            },
        ).one_or_none()
        if row is None:
            raise AccessDenied
        return SessionIdentity(
            row.user_id, row.organization_id, MfaLevel(row.mfa_level)
        )
