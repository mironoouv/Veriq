"""Read grants for an already resolved subject. Authorization is a separate layer."""

from dataclasses import dataclass, field
from datetime import timedelta
from uuid import UUID

from sqlalchemy import Connection, text


@dataclass(frozen=True)
class SessionGate:
    session_id: UUID
    digest: bytes = field(repr=False)
    limits: tuple[timedelta, timedelta, timedelta, timedelta]


def organization_permission_codes(
    connection: Connection,
    *,
    organization_id: UUID,
    user_id: UUID,
    session_gate: SessionGate | None = None,
) -> frozenset[str]:
    result = connection.execute(
        text("""
            SELECT DISTINCT grants.permission_code
            FROM organization_memberships AS membership
            JOIN membership_roles AS assignment
              ON assignment.organization_id = membership.organization_id
             AND assignment.membership_id = membership.id
             AND assignment.grant_epoch = membership.grant_epoch
            JOIN organization_role_permissions AS grants
              ON grants.organization_id = assignment.organization_id
             AND grants.role_id = assignment.role_id
            WHERE membership.organization_id = :organization_id
              AND membership.user_id = :user_id
              AND membership.status = 'active'
              AND public.veriq_active_membership(:organization_id, :subject)
              AND (
                CAST(:session_id AS uuid) IS NULL OR public.veriq_session_current(
                    :session_id, :digest, :user_id, :organization_id, CAST(:limits AS interval[])
                )
              )
        """),
        {
            "organization_id": organization_id,
            "user_id": user_id,
            "subject": str(user_id),
            "session_id": session_gate.session_id if session_gate else None,
            "digest": session_gate.digest if session_gate else None,
            "limits": list(session_gate.limits) if session_gate else None,
        },
    )
    return frozenset(result.scalars())


def platform_permission_codes(
    connection: Connection, *, user_id: UUID
) -> frozenset[str]:
    result = connection.execute(
        text("""
            SELECT DISTINCT grants.permission_code
            FROM platform_role_assignments AS assignment
            JOIN users AS account ON account.id = assignment.user_id
            JOIN platform_role_permissions AS grants ON grants.role_id = assignment.role_id
            WHERE assignment.user_id = :user_id AND account.disabled_at IS NULL
        """),
        {"user_id": user_id},
    )
    return frozenset(result.scalars())
