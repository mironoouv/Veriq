import pytest

from veriq.memberships import MembershipStatus, OrganizationMembership


@pytest.mark.parametrize("status", list(MembershipStatus))
def test_only_active_membership_is_active(status: MembershipStatus) -> None:
    membership = OrganizationMembership(status=status)
    assert membership.is_active == (status is MembershipStatus.ACTIVE)
