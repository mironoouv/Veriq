from dataclasses import replace
from uuid import UUID

import pytest

from veriq.academic_group_teacher_policy import Assignment, Caller, Group, Membership
from veriq.academic_group_transfer_contract import TransferFailure
from veriq.academic_group_transfer_policy import (
    TRANSFER,
    GroupAccess,
    SourceInterval,
    TeacherAuthority,
    authorize_transfer,
    classify_transfer,
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
    assert classify_transfer(caller, SRC, DST, TARGET, INTERVAL) is None


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
    assert (
        classify_transfer(TEACHER, source, destination, TARGET, INTERVAL)
        is TransferFailure.RESOURCE_NOT_FOUND
    )


@pytest.mark.parametrize("caller", [CALLER, TEACHER])
def test_state_conflicts_require_current_access(caller: Caller) -> None:
    archived = replace(DST, group=replace(DST.group, active=False))
    assert (
        classify_transfer(caller, SRC, archived, TARGET, INTERVAL)
        is TransferFailure.TRANSFER_CONFLICT
    )
    assert (
        classify_transfer(caller, SRC, SRC, TARGET, INTERVAL)
        is TransferFailure.TRANSFER_CONFLICT
    )
    denied = replace(caller, permissions=frozenset())
    assert (
        classify_transfer(denied, SRC, archived, TARGET, INTERVAL)
        is TransferFailure.RESOURCE_NOT_FOUND
    )
    closed = replace(INTERVAL, open=False)
    assert (
        classify_transfer(caller, SRC, DST, TARGET, closed)
        is TransferFailure.RESOURCE_NOT_FOUND
    )
    assert (
        classify_transfer(
            caller, SRC, DST, TARGET, closed, access_previously_confirmed=True
        )
        is TransferFailure.TRANSFER_CONFLICT
    )
    assert (
        classify_transfer(
            denied, SRC, DST, TARGET, closed, access_previously_confirmed=True
        )
        is TransferFailure.RESOURCE_NOT_FOUND
    )
    assert (
        classify_transfer(
            replace(caller, session_current=False), SRC, archived, TARGET, closed
        )
        is TransferFailure.SESSION_INVALID
    )


@pytest.mark.parametrize(
    ("caller", "source", "destination", "student", "interval", "expected"),
    [
        (
            replace(CALLER, grant_epoch=2),
            SRC,
            DST,
            TARGET,
            INTERVAL,
            TransferFailure.RESOURCE_NOT_FOUND,
        ),
        (
            replace(CALLER, session_current=False),
            SRC,
            DST,
            TARGET,
            INTERVAL,
            TransferFailure.SESSION_INVALID,
        ),
        (
            replace(CALLER, membership=replace(ADMIN, active=False)),
            SRC,
            DST,
            TARGET,
            INTERVAL,
            TransferFailure.RESOURCE_NOT_FOUND,
        ),
        (
            CALLER,
            SRC,
            replace(DST, group=Group(B, DESTINATION, True)),
            TARGET,
            INTERVAL,
            TransferFailure.RESOURCE_NOT_FOUND,
        ),
        (
            CALLER,
            SRC,
            replace(DST, group=Group(A, DESTINATION, False)),
            TARGET,
            INTERVAL,
            TransferFailure.TRANSFER_CONFLICT,
        ),
        (
            CALLER,
            SRC,
            DST,
            replace(TARGET, organization_id=B),
            INTERVAL,
            TransferFailure.RESOURCE_NOT_FOUND,
        ),
        (
            CALLER,
            SRC,
            DST,
            replace(TARGET, active=False),
            INTERVAL,
            TransferFailure.RESOURCE_NOT_FOUND,
        ),
        (
            CALLER,
            SRC,
            DST,
            TARGET,
            replace(INTERVAL, open=False),
            TransferFailure.RESOURCE_NOT_FOUND,
        ),
        (
            CALLER,
            SRC,
            DST,
            TARGET,
            replace(INTERVAL, group_id=DESTINATION),
            TransferFailure.RESOURCE_NOT_FOUND,
        ),
        (
            CALLER,
            SRC,
            DST,
            TARGET,
            replace(INTERVAL, membership_id=ACTOR),
            TransferFailure.RESOURCE_NOT_FOUND,
        ),
        (CALLER, SRC, SRC, TARGET, INTERVAL, TransferFailure.TRANSFER_CONFLICT),
    ],
)
def test_transfer_rejects_invalid_context(
    caller: Caller,
    source: GroupAccess,
    destination: GroupAccess,
    student: Membership,
    interval: SourceInterval,
    expected: TransferFailure,
) -> None:
    with pytest.raises(AccessDenied):
        authorize_transfer(caller, source, destination, student, interval)
    failure = classify_transfer(caller, source, destination, student, interval)
    assert failure is expected
