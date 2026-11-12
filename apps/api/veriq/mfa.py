"""Trusted MFA verifier using the existing session and credential-proof lifecycle."""

import hmac
import secrets
from dataclasses import dataclass, field
from datetime import timedelta
from enum import StrEnum
from hashlib import sha256
from uuid import UUID, uuid4

from sqlalchemy import Connection, Engine, Row, text

from veriq.auth_audit import RequestContext
from veriq.auth_credentials import CredentialProof
from veriq.mfa_crypto import FactorKeys, matching_counter, seed_text
from veriq.sessions import Sessions, SessionToken
from veriq.tenant_access import AccessDenied


class Purpose(StrEnum):
    SENSITIVE = "sensitive"
    FACTOR_DISABLE = "factor_disable"
    PASSWORD_CHANGE = "password_change"


@dataclass(frozen=True)
class MfaCompletion:
    token: SessionToken
    recovery_codes: tuple[str, ...] = field(default=(), repr=False)


def _audit(
    connection: Connection, context: RequestContext, user: UUID | None, succeeded: bool
) -> None:
    connection.execute(
        text("""SELECT public.veriq_auth_append_event(
            :id, :request, :correlation, 'mfa_attempt', :result, :user, :user, false
        )"""),
        {
            "id": uuid4(),
            "request": context.request_id,
            "correlation": context.correlation_id,
            "result": "succeeded" if succeeded else "denied",
            "user": user,
        },
    )


def _lock(connection: Connection, user: UUID) -> None:
    connection.execute(
        text(
            "SELECT pg_advisory_xact_lock(hashtextextended(CAST(:user AS text), 7007))"
        ),
        {"user": user},
    )


class Mfa:
    def __init__(self, engine: Engine, sessions: Sessions, keys: FactorKeys) -> None:
        self.engine = engine
        self.sessions = Sessions(sessions.engine, sessions.policy, issuer=engine)
        self.keys = keys

    def prepare_enrollment(self, user: UUID, context: RequestContext) -> str:
        """Trusted operator only after independent verification of the intended recipient."""
        seed, factor = secrets.token_bytes(20), uuid4()
        with self.engine.begin() as connection:
            _lock(connection, user)
            if (
                connection.execute(
                    text("SELECT public.veriq_mfa_account(:user, NULL)"),
                    {"user": user},
                ).scalar_one()
                is None
            ):
                raise AccessDenied
            connection.execute(
                text("""DELETE FROM mfa_factors WHERE user_id=:user AND confirmed_at IS NULL
                    AND pending_until <= clock_timestamp()"""),
                {"user": user},
            )
            created = connection.execute(
                text("""INSERT INTO mfa_factors (user_id, id, key_id, ciphertext, pending_until)
                    VALUES (:user, :id, :key, :ciphertext, clock_timestamp() + interval '10 minutes')
                    ON CONFLICT (user_id) DO NOTHING
                    RETURNING id"""),
                {
                    "user": user,
                    "id": factor,
                    "key": self.keys.active,
                    "ciphertext": self.keys.encrypt(user, factor, seed),
                },
            ).scalar_one_or_none()
            if created is None:
                raise AccessDenied
            _audit(connection, context, user, True)
        return seed_text(seed)

    def _challenge(
        self,
        connection: Connection,
        user: UUID,
        factor: UUID,
        organization: UUID | None,
        version: int,
        purpose: str,
        session_id: UUID | None = None,
    ) -> SessionToken:
        token = SessionToken.generate()
        gate = token._gate(self.sessions.policy)
        connection.execute(
            text("""INSERT INTO mfa_challenges (
                id, digest, user_id, factor_id, organization_id, credential_version, purpose, session_id, expires_at
            ) VALUES (:id, :digest, :user, :factor, :org, :version, :purpose, :session,
                      clock_timestamp() + interval '3 minutes')"""),
            {
                "id": gate.session_id,
                "digest": gate.digest,
                "user": user,
                "factor": factor,
                "org": organization,
                "version": version,
                "purpose": purpose,
                "session": session_id,
            },
        )
        return token

    def begin_login(self, proof: CredentialProof) -> SessionToken | None:
        with self.engine.begin() as connection:
            row = connection.execute(
                text(
                    "SELECT * FROM public.veriq_mfa_primary(:id, :digest, CAST(:limits AS interval[]))"
                ),
                {
                    "id": proof.id,
                    "digest": proof.digest,
                    "limits": list(self.sessions.policy.limits),
                },
            ).one_or_none()
            if row is None:
                return None
            factor = connection.execute(
                text("SELECT id, confirmed_at FROM mfa_factors WHERE user_id=:user"),
                {"user": row.user_id},
            ).one()
            purpose = "enroll" if factor.confirmed_at is None else "login"
            return self._challenge(
                connection,
                row.user_id,
                factor.id,
                row.organization_id,
                row.credential_version,
                purpose,
            )

    def begin_step_up(self, token: SessionToken, purpose: Purpose) -> SessionToken:
        gate = token._gate(self.sessions.policy)
        # Resolve in its own transaction so the MFA transaction can acquire account lock first.
        identity = self.sessions.resolve(token)
        with self.engine.begin() as connection:
            _lock(connection, identity.user_id)
            checked = Sessions._use(connection, gate)
            if checked.user_id != identity.user_id:
                raise AccessDenied
            version = connection.execute(
                text("SELECT public.veriq_mfa_account(:user, NULL)"),
                {"user": checked.user_id},
            ).scalar_one()
            factor = connection.execute(
                text(
                    "SELECT id FROM mfa_factors WHERE user_id=:user AND confirmed_at IS NOT NULL"
                ),
                {"user": checked.user_id},
            ).scalar_one_or_none()
            if factor is None or version is None:
                raise AccessDenied
            return self._challenge(
                connection,
                checked.user_id,
                factor,
                checked.organization_id,
                version,
                purpose,
                gate.session_id,
            )

    def challenge_subject(self, token: SessionToken) -> UUID:
        gate = token._gate(self.sessions.policy)
        with self.engine.connect() as connection:
            user: UUID | None = connection.execute(
                text("""SELECT user_id FROM mfa_challenges WHERE id=:id AND digest=:digest
                    AND consumed_at IS NULL AND expires_at > clock_timestamp()"""),
                {"id": gate.session_id, "digest": gate.digest},
            ).scalar_one_or_none()
        if user is None:
            raise AccessDenied
        return user

    def _consume_factor(
        self,
        connection: Connection,
        challenge: Row[tuple[object, ...]],
        code: str,
        recovery: bool,
    ) -> bool:
        factor = connection.execute(
            text("""SELECT id, key_id, ciphertext, last_counter, confirmed_at,
                    pending_until > clock_timestamp() AS pending,
                    floor(extract(epoch FROM clock_timestamp()))::bigint AS tick
                FROM mfa_factors WHERE id=:id AND user_id=:user FOR UPDATE"""),
            {"id": challenge.factor_id, "user": challenge.user_id},
        ).one_or_none()
        enroll = challenge.purpose == "enroll"
        if (
            factor is None
            or (enroll and (not factor.pending or factor.confirmed_at is not None))
            or (not enroll and factor.confirmed_at is None)
        ):
            return False
        if recovery:
            if challenge.purpose != "login" or len(code) != 32 or not code.isascii():
                return False
            rows = connection.execute(
                text(
                    "SELECT salt, digest FROM mfa_recovery_codes WHERE factor_id=:id AND used_at IS NULL"
                ),
                {"id": factor.id},
            )
            for row in rows:
                if hmac.compare_digest(
                    sha256(row.salt + code.encode("ascii")).digest(), row.digest
                ):
                    used = connection.execute(
                        text("""UPDATE mfa_recovery_codes SET used_at=clock_timestamp()
                            WHERE factor_id=:id AND digest=:digest AND used_at IS NULL RETURNING digest"""),
                        {"id": factor.id, "digest": row.digest},
                    ).scalar_one_or_none()
                    return used is not None
            return False

        seed = self.keys.decrypt(
            challenge.user_id, factor.id, factor.key_id, factor.ciphertext
        )
        counter = matching_counter(seed, code, factor.tick)
        if counter is None or counter <= factor.last_counter:
            return False
        updated = connection.execute(
            text("""UPDATE mfa_factors SET last_counter=:counter, key_id=:key, ciphertext=:ciphertext
                WHERE id=:id AND last_counter < :counter RETURNING id"""),
            {
                "id": factor.id,
                "counter": counter,
                "key": self.keys.active,
                "ciphertext": self.keys.encrypt(challenge.user_id, factor.id, seed)
                if factor.key_id != self.keys.active
                else factor.ciphertext,
            },
        ).scalar_one_or_none()
        return updated is not None

    def finish(
        self,
        token: SessionToken,
        code: str,
        *,
        recovery: bool,
        current: SessionToken | None,
        context: RequestContext,
    ) -> MfaCompletion:
        try:
            gate = token._gate(self.sessions.policy)
            user = self.challenge_subject(token)
        except AccessDenied:
            with self.engine.begin() as connection:
                _audit(connection, context, None, False)
            raise
        replacement = None
        codes: tuple[str, ...] = ()
        with self.engine.begin() as connection:
            _lock(connection, user)
            row = connection.execute(
                text("""SELECT * FROM mfa_challenges WHERE id=:id AND digest=:digest
                    AND consumed_at IS NULL AND expires_at > clock_timestamp() FOR UPDATE"""),
                {"id": gate.session_id, "digest": gate.digest},
            ).one_or_none()
            current_gate = (
                current._gate(self.sessions.policy) if current is not None else None
            )
            session_valid = current_gate is None
            if (
                row is not None
                and current_gate is not None
                and row.session_id == current_gate.session_id
            ):
                try:
                    identity = Sessions._use(connection, current_gate)
                    session_valid = (
                        identity.user_id == user
                        and identity.organization_id == row.organization_id
                    )
                except AccessDenied:
                    pass
            accepted = (
                row is not None
                and session_valid
                and row.session_id
                == (current_gate.session_id if current_gate is not None else None)
                and connection.execute(
                    text("SELECT public.veriq_mfa_account(:user, :version)"),
                    {"user": user, "version": row.credential_version},
                ).scalar_one()
                is not None
                and self._consume_factor(connection, row, code, recovery)
            )
            if accepted and row is not None:
                if current_gate is None:
                    if row.purpose == "enroll":
                        codes = self._activate(connection, user, row.factor_id)
                    version = connection.execute(
                        text("SELECT public.veriq_mfa_account(:user, NULL)"),
                        {"user": user},
                    ).scalar_one()
                    proof = CredentialProof(uuid4(), secrets.token_bytes(32))
                    if not connection.execute(
                        text(
                            "SELECT public.veriq_mfa_confirm(:id, :user, :version, :digest, :org)"
                        ),
                        {
                            "id": proof.id,
                            "user": user,
                            "version": version,
                            "digest": proof.digest,
                            "org": row.organization_id,
                        },
                    ).scalar_one():
                        raise AccessDenied
                    replacement, issued = self.sessions._issue_on(
                        connection, proof, context
                    )
                    if issued is not True:
                        raise AccessDenied
                else:
                    replacement = SessionToken.generate()
                    next_gate = replacement._gate(self.sessions.policy)
                    identity = Sessions._use(
                        connection, current_gate, next_gate, row.organization_id
                    )
                    if (
                        identity.user_id != user
                        or identity.organization_id != row.organization_id
                        or identity.mfa_level != 1
                    ):
                        raise AccessDenied
                    connection.execute(
                        text("""INSERT INTO mfa_session_assurance (session_id, purpose, verified_at)
                            VALUES (:id, :purpose, clock_timestamp())"""),
                        {"id": next_gate.session_id, "purpose": row.purpose},
                    )
                    connection.execute(
                        text("""SELECT public.veriq_auth_append_event(
                            :id, :request, :correlation, 'session_rotated', 'succeeded', :user, :user, false
                        )"""),
                        {
                            "id": uuid4(),
                            "request": context.request_id,
                            "correlation": context.correlation_id,
                            "user": user,
                        },
                    )
                connection.execute(
                    text(
                        "UPDATE mfa_challenges SET consumed_at=clock_timestamp() WHERE id=:id"
                    ),
                    {"id": gate.session_id},
                )
            _audit(connection, context, user, accepted)
        if replacement is not None:
            return MfaCompletion(replacement, codes)
        raise AccessDenied

    def _activate(
        self, connection: Connection, user: UUID, factor: UUID
    ) -> tuple[str, ...]:
        connection.execute(
            text("UPDATE mfa_factors SET confirmed_at=clock_timestamp() WHERE id=:id"),
            {"id": factor},
        )
        codes = tuple(secrets.token_urlsafe(24) for _ in range(10))
        for code in codes:
            salt = secrets.token_bytes(16)
            connection.execute(
                text(
                    "INSERT INTO mfa_recovery_codes (factor_id, salt, digest) VALUES (:id, :salt, :digest)"
                ),
                {
                    "id": factor,
                    "salt": salt,
                    "digest": sha256(salt + code.encode("ascii")).digest(),
                },
            )
        connection.execute(
            text("SELECT public.veriq_mfa_reset_sessions(:user)"), {"user": user}
        )
        return codes

    def require_fresh(
        self, connection: Connection, token: SessionToken, purpose: Purpose
    ) -> None:
        gate = token._gate(self.sessions.policy)
        if not connection.execute(
            text("""SELECT public.veriq_mfa_fresh(
                :id, :digest, CAST(:limits AS interval[]), :purpose, CAST(:age AS interval)
            )"""),
            {
                "id": gate.session_id,
                "digest": gate.digest,
                "limits": list(gate.limits),
                "purpose": purpose,
                "age": timedelta(minutes=5),
            },
        ).scalar_one():
            raise AccessDenied

    def disable(self, token: SessionToken, context: RequestContext) -> None:
        identity = self.sessions.resolve(token)
        with self.engine.begin() as connection:
            _lock(connection, identity.user_id)
            self.require_fresh(connection, token, Purpose.FACTOR_DISABLE)
            allowed = bool(
                connection.execute(
                    text(
                        "SELECT public.veriq_mfa_can_disable(:user, CAST(:limits AS interval[]))"
                    ),
                    {
                        "user": identity.user_id,
                        "limits": list(self.sessions.policy.limits),
                    },
                ).scalar_one()
            )
            if allowed:
                connection.execute(
                    text("DELETE FROM mfa_factors WHERE user_id=:user"),
                    {"user": identity.user_id},
                )
                connection.execute(
                    text("SELECT public.veriq_mfa_reset_sessions(:user)"),
                    {"user": identity.user_id},
                )
            _audit(connection, context, identity.user_id, allowed)
        if not allowed:
            raise AccessDenied
