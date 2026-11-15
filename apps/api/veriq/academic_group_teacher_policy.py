"""Pure authorization policy for explicit Teacher assignments to study groups.

Inputs are server-derived snapshots. A future persistence caller must read them
and apply the decision under transaction protection against concurrent changes.
"""

from dataclasses import dataclass
from uuid import UUID

from veriq.tenant_access import AccessDenied

GRANT = "academic.teacher_assignment.grant"
REVOKE = "academic.teacher_assignment.revoke"


@dataclass(frozen=True, slots=True)
class Membership:
    organization_id: UUID
    id: UUID
    grant_epoch: int
    active: bool
    roles: frozenset[str]


@dataclass(frozen=True, slots=True)
class Caller:
    organization_id: UUID
    membership_id: UUID
    grant_epoch: int
    session_current: bool
    membership: Membership
    permissions: frozenset[str]


@dataclass(frozen=True, slots=True)
class Group:
    organization_id: UUID
    id: UUID
    active: bool


@dataclass(frozen=True, slots=True)
class Assignment:
    organization_id: UUID
    group_id: UUID
    membership_id: UUID
    revoked: bool


def _authorize(
    caller: Caller, group: Group, target: Membership, permission: str
) -> None:
    actor = caller.membership
    if not (
        caller.session_current
        and actor.active
        and caller.membership_id == actor.id
        and caller.organization_id
        == actor.organization_id
        == group.organization_id
        == target.organization_id
        and caller.grant_epoch == actor.grant_epoch
        and "org_admin" in actor.roles
        and permission in caller.permissions
    ):
        raise AccessDenied("Teacher assignment denied")


def authorize_grant(caller: Caller, group: Group, target: Membership) -> int:
    """Return the target epoch to persist with an authorized grant."""
    _authorize(caller, group, target, GRANT)
    if not (group.active and target.active and "teacher" in target.roles):
        raise AccessDenied("Teacher assignment denied")
    return target.grant_epoch


def authorize_revoke(
    caller: Caller, group: Group, target: Membership, assignment: Assignment
) -> None:
    _authorize(caller, group, target, REVOKE)
    if not (
        assignment.organization_id == group.organization_id
        and assignment.group_id == group.id
        and assignment.membership_id == target.id
        and not assignment.revoked
    ):
        raise AccessDenied("Teacher assignment denied")
