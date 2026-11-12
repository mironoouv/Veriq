"""PostgreSQL assertions executed only in the disposable migration container."""

import sys
from uuid import UUID

from sqlalchemy import inspect, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from veriq.database import create_database_engine
from veriq.memberships import (
    MembershipStatus,
    Organization,
    OrganizationMembership,
    User,
)

ORG_A = UUID(int=101)
ORG_B = UUID(int=102)
USER = UUID(int=201)
JOB = UUID(int=301)
MISSING = UUID(int=999)
SYNTHETIC_EMAIL = "fixture@example.invalid"
FIXTURE_MARKER = "fixture-only-no-password"


def seed_previous_revision(session: Session) -> None:
    assert not inspect(session.connection()).has_table("organization_memberships")
    for org_id, suffix in [(ORG_A, "a"), (ORG_B, "b")]:
        session.add(
            Organization(
                id=org_id,
                slug=f"fixture-{suffix}",
                display_name="Fixture",
                timezone="UTC",
                status="active",
            )
        )
    session.add(
        User(id=USER, email_normalized=SYNTHETIC_EMAIL, password_hash=FIXTURE_MARKER)
    )
    session.execute(
        text(
            "INSERT INTO background_jobs (id, kind, status, attempts) VALUES (:id, 'probe', 'succeeded', 1)"
        ),
        {"id": JOB},
    )


def verify_previous_rows(session: Session) -> None:
    assert session.scalars(
        select(Organization.slug).order_by(Organization.slug)
    ).all() == ["fixture-a", "fixture-b"]
    user = session.get(User, USER)
    assert user is not None
    assert (user.email_normalized, user.password_hash) == (
        SYNTHETIC_EMAIL,
        FIXTURE_MARKER,
    )
    assert session.execute(
        text("SELECT kind, status, attempts FROM background_jobs WHERE id = :id"),
        {"id": JOB},
    ).one() == ("probe", "succeeded", 1)


def expect_constraint(
    session: Session, statement: str, constraint: str, **parameters: object
) -> None:
    try:
        with session.begin_nested():
            session.execute(text(statement), parameters)
    except IntegrityError as error:
        if (
            getattr(getattr(error.orig, "diag", None), "constraint_name", None)
            != constraint
        ):
            raise
    else:
        raise AssertionError(f"Expected PostgreSQL constraint {constraint}")


def check_membership_constraints(session: Session) -> None:
    first = OrganizationMembership(organization_id=ORG_A, user_id=USER)
    second = OrganizationMembership(
        organization_id=ORG_B, user_id=USER, status=MembershipStatus.ACTIVE
    )
    session.add_all([first, second])
    session.flush()
    assert first.status is MembershipStatus.PENDING
    assert not first.is_active and second.is_active
    assert first.created_at.tzinfo is not None
    assert first.updated_at.tzinfo is not None

    for version, status in enumerate(
        (MembershipStatus.ACTIVE, MembershipStatus.SUSPENDED, MembershipStatus.REVOKED),
        start=2,
    ):
        first.status = status
        session.flush()
        assert first.version == version
        assert first.is_active == (status is MembershipStatus.ACTIVE)
    assert second.is_active

    insert = """
        INSERT INTO organization_memberships (id, organization_id, user_id)
        VALUES (:id, :org, :account)
    """
    expect_constraint(
        session,
        insert,
        "uq_memberships_organization_user",
        id=MISSING,
        org=ORG_A,
        account=USER,
    )
    expect_constraint(
        session,
        insert,
        "fk_memberships_organization",
        id=MISSING,
        org=MISSING,
        account=USER,
    )
    expect_constraint(
        session, insert, "fk_memberships_user", id=MISSING, org=ORG_A, account=MISSING
    )
    expect_constraint(
        session,
        "UPDATE organization_memberships SET status = 'unknown' WHERE id = :id",
        "ck_memberships_status",
        id=first.id,
    )
    expect_constraint(
        session, "DELETE FROM users WHERE id = :id", "fk_memberships_user", id=USER
    )
    expect_constraint(
        session,
        "DELETE FROM organizations WHERE id = :id",
        "fk_memberships_organization",
        id=ORG_A,
    )


def verify_persistence(session: Session) -> None:
    verify_previous_rows(session)
    rows = session.execute(
        select(
            OrganizationMembership.organization_id,
            OrganizationMembership.status,
            OrganizationMembership.version,
        )
        .where(OrganizationMembership.user_id == USER)
        .order_by(OrganizationMembership.organization_id)
    ).all()
    assert [
        (organization_id, status, version) for organization_id, status, version in rows
    ] == [
        (ORG_A, MembershipStatus.REVOKED, 4),
        (ORG_B, MembershipStatus.ACTIVE, 1),
    ]


def main() -> None:
    engine = create_database_engine()
    try:
        with Session(engine) as session, session.begin():
            match sys.argv[1]:
                case "seed":
                    seed_previous_revision(session)
                case "upgrade":
                    verify_previous_rows(session)
                    check_membership_constraints(session)
                case "persist":
                    verify_persistence(session)
                case _:
                    raise ValueError("Unknown membership test mode")
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
