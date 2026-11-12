"""Typed security events and leased notification delivery."""

from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID, uuid4

from sqlalchemy import Connection, text


class AuthEvent(StrEnum):
    REGISTRATION = "registration_attempt"
    LOGIN = "login_attempt"
    MFA = "mfa_attempt"
    PASSWORD_RESET = "password_reset_attempt"
    MFA_RECOVERY = "mfa_recovery_attempt"
    PASSWORD_VERIFIED = "password_verified"
    LOGIN_MFA_REQUIRED = "login_mfa_required"
    SESSION_ROTATED = "session_rotated"
    SESSION_ISSUED = "session_issued"
    SESSION_REVOKED = "session_revoked"
    SESSIONS_REVOKED = "sessions_revoked"


class AuthResult(StrEnum):
    SUCCEEDED = "succeeded"
    DENIED = "denied"
    FAILED = "failed"


@dataclass(frozen=True)
class RequestContext:
    request_id: UUID
    correlation_id: UUID

    @classmethod
    def new(cls) -> "RequestContext":
        request_id = uuid4()
        return cls(request_id, request_id)


def append_attempt(
    connection: Connection,
    event_id: UUID,
    context: RequestContext,
    event_type: AuthEvent,
    result: AuthResult,
    *,
    actor: UUID | None = None,
    target: UUID | None = None,
) -> bool:
    accepted: bool = connection.execute(
        text("""SELECT public.veriq_auth_append_attempt(
            :event, :request, :correlation, :type, :result, :actor, :target
        )"""),
        {
            "event": event_id,
            "request": context.request_id,
            "correlation": context.correlation_id,
            "type": event_type.value,
            "result": result.value,
            "actor": actor,
            "target": target,
        },
    ).scalar_one()
    return accepted


@dataclass(frozen=True)
class Notice:
    event_id: UUID
    claim_id: UUID
    target_id: UUID
    event_type: AuthEvent


def claim_notice(connection: Connection) -> Notice | None:
    claim_id = uuid4()
    row = connection.execute(
        text("SELECT * FROM public.veriq_auth_claim_notice(:claim)"),
        {"claim": claim_id},
    ).one_or_none()
    if row is None:
        return None
    return Notice(row.event_id, claim_id, row.target_id, AuthEvent(row.event_type))


def acknowledge_notice(connection: Connection, notice: Notice) -> bool:
    accepted: bool = connection.execute(
        text("SELECT public.veriq_auth_ack_notice(:event, :claim)"),
        {"event": notice.event_id, "claim": notice.claim_id},
    ).scalar_one()
    return accepted
