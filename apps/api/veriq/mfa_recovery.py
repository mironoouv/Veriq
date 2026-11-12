"""Independent recovery service. All authorization and transitions are database guarded."""

import os
import re
import secrets
from enum import StrEnum
from hashlib import sha256
from uuid import UUID, uuid4

from sqlalchemy import Engine, text

from veriq.auth_audit import RequestContext
from veriq.auth_credentials import CredentialProof
from veriq.mfa_crypto import FactorKeys, matching_counter, seed_text
from veriq.sessions import SessionPolicy, SessionToken
from veriq.tenant_access import AccessDenied


class RecoveryAction(StrEnum):
    VERIFY = "verify"
    APPROVE = "approve"
    DISPUTE = "dispute"
    REOPEN = "reopen"
    RELEASE = "release"


def recovery_enabled() -> bool:
    return (
        os.environ.get("VERIQ_ENV") == "test"
        and os.environ.get("VERIQ_ENABLE_TEST_MFA_RECOVERY") == "1"
    )


class MfaRecovery:
    def __init__(
        self, api: Engine, verifier: Engine, policy: SessionPolicy, keys: FactorKeys
    ) -> None:
        self.api = api
        self.verifier = verifier
        self.policy = policy
        self.keys = keys

    def start(self, proof: CredentialProof, context: RequestContext) -> None:
        with self.api.begin() as connection:
            connection.execute(
                text(
                    "SELECT public.veriq_recovery_start(:id,:hash,:event,:request,:correlation)"
                ),
                {
                    "id": proof.id,
                    "hash": proof.digest,
                    "event": uuid4(),
                    "request": context.request_id,
                    "correlation": context.correlation_id,
                },
            )

    def transition(
        self,
        token: SessionToken,
        case: UUID,
        action: RecoveryAction,
        operation: UUID,
        context: RequestContext,
        source_id: UUID | None = None,
    ) -> str | None:
        gate = token._gate(self.policy)
        secret = secrets.token_urlsafe(32) if action is RecoveryAction.RELEASE else None
        with self.api.begin() as connection:
            result = connection.execute(
                text("""SELECT public.veriq_recovery_transition(
                    :id,:hash,CAST(:limits AS interval[]),:case,:action,:event,:digest,:correlation,:source
                )"""),
                {
                    "id": gate.session_id,
                    "hash": gate.digest,
                    "limits": list(gate.limits),
                    "case": case,
                    "action": action.value,
                    "event": operation,
                    "digest": sha256(secret.encode("ascii")).digest()
                    if secret
                    else None,
                    "correlation": context.correlation_id,
                    "source": source_id,
                },
            ).scalar_one()
        if result not in ("applied", "replayed"):
            raise AccessDenied
        return secret if result == "applied" else None

    @staticmethod
    def _binding(capability: str, nonce: str) -> dict[str, bytes]:
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", capability) or not re.fullmatch(
            r"[A-Za-z0-9_-]{43}", nonce
        ):
            raise AccessDenied
        return {
            "digest": sha256(capability.encode("ascii")).digest(),
            "binding": sha256(nonce.encode("ascii")).digest(),
        }

    def prepare(
        self,
        case: UUID,
        capability: str,
        nonce: str,
        user: UUID,
        proof: CredentialProof,
    ) -> str:
        params = self._binding(capability, nonce)
        factor = UUID(bytes=secrets.token_bytes(16), version=4)
        seed = secrets.token_bytes(20)
        with self.verifier.begin() as connection:
            row = connection.execute(
                text("""SELECT * FROM public.veriq_recovery_enrollment(
                    :case,:digest,:binding,:proof,:proof_hash,:factor,:key,:ciphertext
                )"""),
                {
                    **params,
                    "case": case,
                    "proof": proof.id,
                    "proof_hash": proof.digest,
                    "factor": factor,
                    "key": self.keys.active,
                    "ciphertext": self.keys.encrypt(user, factor, seed),
                },
            ).one_or_none()
            if row is None:
                raise AccessDenied
            return seed_text(
                self.keys.decrypt(
                    row.user_id, row.factor_id, row.key_id, row.ciphertext
                )
            )

    def complete(
        self,
        case: UUID,
        capability: str,
        nonce: str,
        code: str,
        context: RequestContext,
    ) -> tuple[str, ...]:
        params = self._binding(capability, nonce)
        codes = tuple(secrets.token_urlsafe(24) for _ in range(10))
        salts = [secrets.token_bytes(16) for _ in codes]
        with self.verifier.begin() as connection:
            row = connection.execute(
                text("""SELECT * FROM public.veriq_recovery_enrollment(
                    :case,:digest,:binding,NULL,NULL,NULL,NULL,NULL
                )"""),
                {**params, "case": case},
            ).one_or_none()
            if row is None:
                raise AccessDenied
            tick = connection.execute(
                text("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            ).scalar_one()
            seed = self.keys.decrypt(
                row.user_id, row.factor_id, row.key_id, row.ciphertext
            )
            counter = matching_counter(seed, code, tick)
            if counter is None:
                connection.execute(
                    text(
                        "SELECT public.veriq_recovery_reject(:case,:digest,:binding,:event,:correlation)"
                    ),
                    {
                        **params,
                        "case": case,
                        "event": context.request_id,
                        "correlation": context.correlation_id,
                    },
                )
            elif not connection.execute(
                text("""SELECT public.veriq_recovery_complete(
                    :case,:digest,:binding,:counter,CAST(:salts AS bytea[]),CAST(:codes AS bytea[]),:event,:correlation
                )"""),
                {
                    **params,
                    "case": case,
                    "counter": counter,
                    "salts": salts,
                    "codes": [
                        sha256(salt + value.encode("ascii")).digest()
                        for salt, value in zip(salts, codes, strict=True)
                    ],
                    "event": context.request_id,
                    "correlation": context.correlation_id,
                },
            ).scalar_one():
                raise AccessDenied
        if counter is None:
            raise AccessDenied
        return codes
