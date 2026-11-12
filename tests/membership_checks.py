"""PostgreSQL assertions executed only in the disposable migration container."""

import sys
from concurrent.futures import ThreadPoolExecutor
from time import monotonic, sleep
from uuid import UUID

from sqlalchemy import Engine, inspect, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from veriq.database import create_database_engine
from veriq.memberships import (
    MembershipStatus,
    Organization,
    OrganizationMembership,
    User,
)
from veriq.permissions import organization_permission_codes, platform_permission_codes

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


def seed_legacy_grants(session: Session) -> None:
    # 0004 could already contain grants whose revocation history is unknown.
    session.execute(
        text("INSERT INTO permissions VALUES ('organization', 'fixture.legacy')")
    )
    session.execute(
        text("INSERT INTO organization_roles VALUES (:org, :role, 'technician')"),
        {"org": ORG_B, "role": UUID(int=450)},
    )
    session.execute(
        text("""
        INSERT INTO organization_role_permissions (organization_id, role_id, permission_code)
        VALUES (:org, :role, 'fixture.legacy')
    """),
        {"org": ORG_B, "role": UUID(int=450)},
    )
    session.execute(
        text("""
        INSERT INTO membership_roles (organization_id, membership_id, role_id)
        SELECT organization_id, id, :role FROM organization_memberships
        WHERE organization_id = :org AND user_id = :account
    """),
        {"org": ORG_B, "account": USER, "role": UUID(int=450)},
    )


def check_concurrent_revocation(engine: Engine) -> None:
    revoke = "UPDATE organization_memberships SET status = 'revoked' WHERE organization_id = :org AND user_id = :account"
    reactivate = "UPDATE organization_memberships SET status = 'active' WHERE organization_id = :org AND user_id = :account"
    assign = """
        INSERT INTO membership_roles (organization_id, membership_id, role_id)
        SELECT organization_id, id, :role FROM organization_memberships
        WHERE organization_id = :org AND user_id = :account
    """
    params = {"org": ORG_A, "account": USER, "role": UUID(int=401)}

    def race(first: str, second: str, expected: str | None) -> None:
        with engine.begin() as connection:
            connection.execute(text(reactivate), params)
        with engine.connect() as waiting, engine.connect() as observer:
            pid = waiting.execute(text("SELECT pg_backend_pid()")).scalar_one()
            waiting.commit()

            def run_waiting_statement() -> str | None:
                try:
                    with waiting.begin():
                        waiting.execute(text("SET LOCAL lock_timeout = '10s'"))
                        waiting.execute(text(second), params)
                except IntegrityError as error:
                    return getattr(
                        getattr(error.orig, "diag", None), "constraint_name", None
                    )
                return None

            with ThreadPoolExecutor(max_workers=1) as executor:
                with engine.begin() as holding:
                    holding.execute(text(first), params)
                    future = executor.submit(run_waiting_statement)
                    deadline = monotonic() + 5
                    while not observer.execute(
                        text("SELECT cardinality(pg_blocking_pids(:pid))"), {"pid": pid}
                    ).scalar_one():
                        assert monotonic() < deadline, (
                            "Expected a real PostgreSQL row lock wait"
                        )
                        sleep(0.025)
                assert future.result(timeout=12) == expected
        with engine.begin() as connection:
            connection.execute(text(reactivate), params)
            assert (
                organization_permission_codes(
                    connection, organization_id=ORG_A, user_id=USER
                )
                == frozenset()
            )

    race(assign, revoke, None)
    race(revoke, assign, "ck_membership_roles_active")
    print("Concurrent grant/revocation passed in both lock orders.")


def check_role_constraints(session: Session) -> None:
    # Membership rows were committed before upgrading from revision 0003.
    membership_a = session.scalars(
        select(OrganizationMembership).where(
            OrganizationMembership.organization_id == ORG_A
        )
    ).one()
    membership_b = session.scalars(
        select(OrganizationMembership).where(
            OrganizationMembership.organization_id == ORG_B
        )
    ).one()
    admin, proctor, student, superadmin = (UUID(int=value) for value in range(401, 405))

    def execute(statement: str, **parameters: object) -> None:
        session.execute(text(statement), parameters)

    def org_grants(organization_id: UUID) -> frozenset[str]:
        return organization_permission_codes(
            session.connection(), organization_id=organization_id, user_id=USER
        )

    assign = """
        INSERT INTO membership_roles (organization_id, membership_id, role_id)
        VALUES (:org, :member, :role)
    """
    execute(
        "INSERT INTO permissions VALUES ('platform', 'platform.manage'), "
        "('organization', 'fixture.admin'), ('organization', 'fixture.observe'), "
        "('organization', 'fixture.learn')"
    )
    execute(
        "INSERT INTO platform_roles (id, code) VALUES (:role, 'superadmin')",
        role=superadmin,
    )
    execute(
        "INSERT INTO platform_role_assignments VALUES (:account, :role)",
        account=USER,
        role=superadmin,
    )
    execute(
        "INSERT INTO platform_role_permissions (role_id, permission_code) VALUES (:role, 'platform.manage')",
        role=superadmin,
    )
    assert platform_permission_codes(session.connection(), user_id=USER) == {
        "platform.manage"
    }
    assert org_grants(ORG_A) == org_grants(ORG_B) == frozenset()
    assert (
        session.execute(text("SELECT count(*) FROM membership_roles")).scalar_one() == 1
    )
    expect_constraint(
        session,
        "INSERT INTO platform_role_assignments VALUES (:account, :role)",
        "platform_role_assignments_pkey",
        account=USER,
        role=superadmin,
    )
    expect_constraint(
        session,
        "INSERT INTO platform_role_permissions (role_id, permission_code) VALUES (:role, 'fixture.admin')",
        "fk_platform_role_permissions_permission",
        role=superadmin,
    )

    for organization_id, role_id, code, permission in [
        (ORG_A, admin, "org_admin", "fixture.admin"),
        (ORG_A, proctor, "proctor", "fixture.observe"),
        (ORG_B, student, "student", "fixture.learn"),
    ]:
        execute(
            "INSERT INTO organization_roles VALUES (:org, :role, :code)",
            org=organization_id,
            role=role_id,
            code=code,
        )
        execute(
            "INSERT INTO organization_role_permissions (organization_id, role_id, permission_code) VALUES (:org, :role, :permission)",
            org=organization_id,
            role=role_id,
            permission=permission,
        )

    for status in (
        MembershipStatus.PENDING,
        MembershipStatus.SUSPENDED,
        MembershipStatus.REVOKED,
    ):
        membership_a.status = status
        session.flush()
        expect_constraint(
            session,
            assign,
            "ck_membership_roles_active",
            org=ORG_A,
            member=membership_a.id,
            role=admin,
        )
        assert org_grants(ORG_A) == frozenset()

    membership_a.status = MembershipStatus.ACTIVE
    session.flush()
    execute(assign, org=ORG_A, member=membership_a.id, role=admin)
    execute(assign, org=ORG_A, member=membership_a.id, role=proctor)
    assert org_grants(ORG_B) == frozenset()
    execute(assign, org=ORG_B, member=membership_b.id, role=student)
    assert org_grants(ORG_A) == {"fixture.admin", "fixture.observe"}
    assert org_grants(ORG_B) == {"fixture.learn"}

    membership_a.status = MembershipStatus.SUSPENDED
    session.flush()
    assert org_grants(ORG_A) == frozenset()
    membership_a.status = MembershipStatus.ACTIVE
    session.flush()
    assert org_grants(ORG_A) == {"fixture.admin", "fixture.observe"}

    expect_constraint(
        session,
        assign,
        "membership_roles_pkey",
        org=ORG_A,
        member=membership_a.id,
        role=admin,
    )
    expect_constraint(
        session,
        assign,
        "fk_membership_roles_role",
        org=ORG_A,
        member=membership_a.id,
        role=student,
    )
    expect_constraint(
        session,
        assign,
        "ck_membership_roles_active",
        org=ORG_A,
        member=membership_b.id,
        role=admin,
    )
    expect_constraint(
        session,
        assign,
        "fk_membership_roles_role",
        org=ORG_A,
        member=membership_a.id,
        role=MISSING,
    )
    expect_constraint(
        session,
        assign,
        "fk_membership_roles_role",
        org=ORG_A,
        member=membership_a.id,
        role=superadmin,
    )
    expect_constraint(
        session,
        "INSERT INTO organization_role_permissions (organization_id, role_id, permission_code) VALUES (:org, :role, 'platform.manage')",
        "fk_organization_role_permissions_permission",
        org=ORG_A,
        role=admin,
    )
    expect_constraint(
        session,
        "UPDATE membership_roles SET role_id = :foreign_role WHERE organization_id = :org AND membership_id = :member AND role_id = :role",
        "ck_membership_roles_immutable",
        org=ORG_A,
        member=membership_a.id,
        role=admin,
        foreign_role=student,
    )

    for status in (
        MembershipStatus.SUSPENDED,
        MembershipStatus.PENDING,
        MembershipStatus.REVOKED,
    ):
        membership_a.status = status
        session.flush()
        assert org_grants(ORG_A) == frozenset()
        assert org_grants(ORG_B) == {"fixture.learn"}
    assert (
        session.execute(
            text(
                "SELECT count(*) FROM membership_roles WHERE organization_id = :org AND membership_id = :member"
            ),
            {"org": ORG_A, "member": membership_a.id},
        ).scalar_one()
        == 2
    )

    # Reuse the same session and connection to verify no old role is restored.
    membership_a.status = MembershipStatus.ACTIVE
    session.flush()
    assert org_grants(ORG_A) == frozenset()
    assert org_grants(ORG_B) == {"fixture.learn"}
    print("Revoked → active: historical grants did not restore permissions.")
    execute(assign, org=ORG_A, member=membership_a.id, role=admin)
    assert org_grants(ORG_A) == {"fixture.admin"}
    expect_constraint(
        session,
        assign,
        "membership_roles_pkey",
        org=ORG_A,
        member=membership_a.id,
        role=admin,
    )
    membership_b.status = MembershipStatus.REVOKED
    session.flush()
    membership_b.status = MembershipStatus.ACTIVE
    session.flush()
    membership_a.status = MembershipStatus.REVOKED
    session.flush()
    assert org_grants(ORG_A) == org_grants(ORG_B) == frozenset()


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
                case "legacy-grants":
                    seed_legacy_grants(session)
                case "roles":
                    verify_persistence(session)
                    check_role_constraints(session)
                case _:
                    raise ValueError("Unknown membership test mode")
        if sys.argv[1] == "roles":
            check_concurrent_revocation(engine)
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
