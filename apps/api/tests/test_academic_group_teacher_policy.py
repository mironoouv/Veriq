from dataclasses import replace
from uuid import UUID

import pytest

from veriq.academic_group_teacher_policy import (
    GRANT,
    REVOKE,
    Assignment,
    Caller,
    Group,
    Membership,
    authorize_grant,
    authorize_revoke,
)
from veriq.tenant_access import AccessDenied

A, B, ADMIN, TEACHER, GROUP = (UUID(int=i) for i in range(1, 6))
ACTOR = Membership(A, ADMIN, 2, True, frozenset({"org_admin"}))
CALLER = Caller(A, ADMIN, 2, True, ACTOR, frozenset({GRANT, REVOKE}))
TARGET = Membership(A, TEACHER, 5, True, frozenset({"teacher"}))
RESOURCE = Group(A, GROUP, True)
ASSIGNMENT = Assignment(A, GROUP, TEACHER, False)


def test_grant_and_revoke() -> None:
    assert authorize_grant(CALLER, RESOURCE, TARGET) == 5
    authorize_revoke(CALLER, RESOURCE, TARGET, ASSIGNMENT)


@pytest.mark.parametrize(
    "caller",
    [
        replace(CALLER, session_current=False),
        replace(CALLER, grant_epoch=1),
        replace(CALLER, membership_id=TEACHER),
        replace(CALLER, membership=replace(ACTOR, active=False)),
        replace(CALLER, membership=replace(ACTOR, organization_id=B)),
        replace(CALLER, membership=replace(ACTOR, roles=frozenset({"teacher"}))),
    ],
)
def test_invalid_actor_denied_for_both_operations(caller: Caller) -> None:
    with pytest.raises(AccessDenied):
        authorize_grant(caller, RESOURCE, TARGET)
    with pytest.raises(AccessDenied):
        authorize_revoke(caller, RESOURCE, TARGET, ASSIGNMENT)


def test_permissions_are_independent() -> None:
    with pytest.raises(AccessDenied):
        authorize_grant(
            replace(CALLER, permissions=frozenset({REVOKE})), RESOURCE, TARGET
        )
    with pytest.raises(AccessDenied):
        authorize_revoke(
            replace(CALLER, permissions=frozenset({GRANT})),
            RESOURCE,
            TARGET,
            ASSIGNMENT,
        )


@pytest.mark.parametrize(
    ("group", "target"),
    [
        (replace(RESOURCE, organization_id=B), TARGET),
        (RESOURCE, replace(TARGET, organization_id=B)),
    ],
)
def test_cross_tenant_denied(group: Group, target: Membership) -> None:
    with pytest.raises(AccessDenied):
        authorize_grant(CALLER, group, target)
    with pytest.raises(AccessDenied):
        authorize_revoke(CALLER, group, target, ASSIGNMENT)


@pytest.mark.parametrize(
    ("group", "target"),
    [
        (replace(RESOURCE, active=False), TARGET),
        (RESOURCE, replace(TARGET, active=False, grant_epoch=6)),
        (RESOURCE, replace(TARGET, roles=frozenset({"student"}))),
    ],
)
def test_grant_fails_but_existing_assignment_can_be_revoked(
    group: Group, target: Membership
) -> None:
    with pytest.raises(AccessDenied):
        authorize_grant(CALLER, group, target)
    authorize_revoke(CALLER, group, target, ASSIGNMENT)


@pytest.mark.parametrize(
    "assignment",
    [
        replace(ASSIGNMENT, organization_id=B),
        replace(ASSIGNMENT, group_id=ADMIN),
        replace(ASSIGNMENT, membership_id=ADMIN),
        replace(ASSIGNMENT, revoked=True),
    ],
)
def test_revoke_requires_matching_open_assignment(assignment: Assignment) -> None:
    with pytest.raises(AccessDenied):
        authorize_revoke(CALLER, RESOURCE, TARGET, assignment)
