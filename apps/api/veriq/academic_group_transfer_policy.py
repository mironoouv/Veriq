"""Authorize transfers using server snapshots refreshed inside the future write transaction."""

from dataclasses import dataclass
from uuid import UUID

from veriq.academic_group_teacher_policy import Assignment, Caller, Group, Membership
from veriq.tenant_access import AccessDenied

TRANSFER = "academic.roster.transfer"


@dataclass(frozen=True, slots=True)
class TeacherAuthority:
    assignment: Assignment
    grant_epoch: int


@dataclass(frozen=True, slots=True)
class GroupAccess:
    group: Group
    permissions: frozenset[str]
    teacher: TeacherAuthority | None = None


@dataclass(frozen=True, slots=True)
class SourceInterval:
    organization_id: UUID
    group_id: UUID
    membership_id: UUID
    open: bool


def _can_transfer(actor: Membership, access: GroupAccess) -> bool:
    if TRANSFER not in access.permissions:
        return False
    if "org_admin" in actor.roles:
        return True
    authority = access.teacher
    if "teacher" not in actor.roles or authority is None:
        return False
    assignment = authority.assignment
    return (
        not assignment.revoked
        and assignment.organization_id == actor.organization_id
        and assignment.group_id == access.group.id
        and assignment.membership_id == actor.id
        and authority.grant_epoch == actor.grant_epoch
    )


def authorize_transfer(
    caller: Caller,
    source: GroupAccess,
    destination: GroupAccess,
    student: Membership,
    interval: SourceInterval,
) -> None:
    """Check eligibility without writing intervals or issuing permissions."""
    actor = caller.membership
    if not (
        caller.session_current
        and actor.active
        and actor.id == caller.membership_id
        and actor.grant_epoch == caller.grant_epoch
        and caller.organization_id
        == actor.organization_id
        == source.group.organization_id
        == destination.group.organization_id
        == student.organization_id
        == interval.organization_id
        and source.group.id != destination.group.id
        and destination.group.active
        and interval.open
        and interval.group_id == source.group.id
        and interval.membership_id == student.id
        and student.active
        and "student" in student.roles
        and TRANSFER in caller.permissions
        and _can_transfer(actor, source)
        and _can_transfer(actor, destination)
    ):
        raise AccessDenied("Student transfer denied")
