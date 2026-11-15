from dataclasses import replace
from uuid import UUID

import pytest

from veriq.academic_group_teacher_policy import Assignment, Caller, Group, Membership
from veriq.academic_group_transfer_policy import (
    TRANSFER,
    GroupAccess,
    SourceInterval,
    TeacherAuthority,
    authorize_transfer,
)
from veriq.tenant_access import AccessDenied

A, B, ACTOR, STUDENT, SOURCE, DESTINATION = (UUID(int=i) for i in range(1, 7))
PERMISSIONS = frozenset({TRANSFER})
ADMIN = Membership(A, ACTOR, 3, True, frozenset({"org_admin"}))
CALLER = Caller(A, ACTOR, 3, True, ADMIN, PERMISSIONS)
TEACHER = replace(CALLER, membership=replace(ADMIN, roles=frozenset({"teacher"})))
TARGET = Membership(A, STUDENT, 1, True, frozenset({"student"}))
INTERVAL = SourceInterval(A, SOURCE, STUDENT, True)


def access(group: UUID) -> GroupAccess:
    return GroupAccess(
        Group(A, group, True),
        PERMISSIONS,
        TeacherAuthority(Assignment(A, group, ACTOR, False), 3),
    )


SRC, DST = access(SOURCE), access(DESTINATION)


@pytest.mark.parametrize("caller", [CALLER, TEACHER])
def test_transfer_allowed(caller: Caller) -> None:
    authorize_transfer(caller, SRC, DST, TARGET, INTERVAL)


@pytest.mark.parametrize(
    ("source", "destination"),
    [
        (replace(SRC, teacher=None), DST),
        (SRC, replace(DST, teacher=None)),
        (replace(SRC, permissions=frozenset()), DST),
        (SRC, replace(DST, permissions=frozenset())),
        (
            SRC,
            replace(
                DST,
                teacher=TeacherAuthority(Assignment(A, DESTINATION, ACTOR, True), 3),
            ),
        ),
        (
            SRC,
            replace(
                DST,
                teacher=TeacherAuthority(Assignment(A, DESTINATION, ACTOR, False), 2),
            ),
        ),
        (SRC, replace(DST, teacher=SRC.teacher)),
    ],
)
def test_teacher_needs_current_authority_on_both_groups(
    source: GroupAccess, destination: GroupAccess
) -> None:
    with pytest.raises(AccessDenied):
        authorize_transfer(TEACHER, source, destination, TARGET, INTERVAL)


@pytest.mark.parametrize(
    ("caller", "source", "destination", "student", "interval"),
    [
        (replace(CALLER, grant_epoch=2), SRC, DST, TARGET, INTERVAL),
        (replace(CALLER, session_current=False), SRC, DST, TARGET, INTERVAL),
        (
            replace(CALLER, membership=replace(ADMIN, active=False)),
            SRC,
            DST,
            TARGET,
            INTERVAL,
        ),
        (
            CALLER,
            SRC,
            replace(DST, group=Group(B, DESTINATION, True)),
            TARGET,
            INTERVAL,
        ),
        (
            CALLER,
            SRC,
            replace(DST, group=Group(A, DESTINATION, False)),
            TARGET,
            INTERVAL,
        ),
        (CALLER, SRC, DST, replace(TARGET, organization_id=B), INTERVAL),
        (CALLER, SRC, DST, replace(TARGET, active=False), INTERVAL),
        (CALLER, SRC, DST, TARGET, replace(INTERVAL, open=False)),
        (CALLER, SRC, DST, TARGET, replace(INTERVAL, group_id=DESTINATION)),
        (CALLER, SRC, DST, TARGET, replace(INTERVAL, membership_id=ACTOR)),
        (CALLER, SRC, SRC, TARGET, INTERVAL),
    ],
)
def test_transfer_rejects_invalid_context(
    caller: Caller,
    source: GroupAccess,
    destination: GroupAccess,
    student: Membership,
    interval: SourceInterval,
) -> None:
    with pytest.raises(AccessDenied):
        authorize_transfer(caller, source, destination, student, interval)
