"""TEN-01 integration checks in the disposable identity database."""

import os
from collections.abc import Callable
from functools import partial
from uuid import UUID

from sqlalchemy import Connection, Engine, create_engine, text
from sqlalchemy.exc import DBAPIError
from veriq.database import create_database_engine, database_url
from veriq.tenant_access import (
    AccessDenied,
    ResourcePolicy,
    TenantResource,
    VerifiedSubject,
    tenant_transaction,
)

A, B, OLD_SUBJECT = (UUID(int=value) for value in (101, 102, 201))
ALICE, BOB, PLATFORM = (VerifiedSubject(UUID(int=value)) for value in range(601, 604))
MEMBER_A, MEMBER_B, ROLE_A, ROLE_B = (UUID(int=value) for value in range(611, 615))
PROBE_ROLE = UUID(int=620)
POLICY = ResourcePolicy("fixture.admin")
OWNER_POLICY = ResourcePolicy("fixture.admin", owner_only=True)


def deny(operation: Callable[[], object]) -> None:
    try:
        operation()
    except AccessDenied:
        return
    raise AssertionError("Expected application authorization denial")


def sql_denied(connection: Connection, statement: str, **params: object) -> None:
    try:
        with connection.begin_nested():
            connection.execute(text(statement), params)
    except DBAPIError as error:
        assert getattr(error.orig, "sqlstate", None) == "42501"
    else:
        raise AssertionError("Expected PostgreSQL insufficient privilege")


def set_scope(connection: Connection, organization: str, subject: str) -> None:
    connection.execute(
        text("""SELECT set_config('veriq.organization_id', :org, true),
                       set_config('veriq.user_id', :subject, true)"""),
        {"org": organization, "subject": subject},
    )


def tenant_ids(connection: Connection) -> set[UUID]:
    return set(connection.execute(text("SELECT id FROM organizations")).scalars())


def seed(engine: Engine) -> None:
    with engine.begin() as connection:
        for number, subject in enumerate((ALICE, BOB, PLATFORM), start=1):
            connection.execute(
                text("""INSERT INTO users (id, email_normalized, password_hash)
                        VALUES (:user, :email, 'fixture-only-no-password')"""),
                {
                    "user": subject.user_id,
                    "email": f"tenant-fixture-{number}@example.invalid",
                },
            )
        for org, subject, member, role, code in [
            (A, ALICE, MEMBER_A, ROLE_A, "student"),
            (B, BOB, MEMBER_B, ROLE_B, "teacher"),
        ]:
            params = {
                "org": org,
                "user": subject.user_id,
                "member": member,
                "role": role,
                "code": code,
            }
            connection.execute(
                text("""
                INSERT INTO organization_memberships (organization_id, user_id, id, status)
                VALUES (:org, :user, :member, 'active')
            """),
                params,
            )
            connection.execute(
                text("INSERT INTO organization_roles VALUES (:org, :role, :code)"),
                params,
            )
            connection.execute(
                text("""
                INSERT INTO organization_role_permissions (organization_id, role_id, permission_code)
                VALUES (:org, :role, 'fixture.admin')
            """),
                params,
            )
            connection.execute(
                text("""
                INSERT INTO membership_roles (organization_id, membership_id, role_id)
                VALUES (:org, :member, :role)
            """),
                params,
            )
        connection.execute(
            text("""INSERT INTO platform_role_assignments
                    SELECT :user, id FROM platform_roles WHERE code = 'superadmin'"""),
            {"user": PLATFORM.user_id},
        )


def verify_runtime_role(connection: Connection, role: str) -> None:
    assert connection.execute(text("SELECT current_user")).scalar_one() == role
    assert connection.execute(
        text("""
        SELECT NOT (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolinherit)
        FROM pg_roles WHERE rolname = current_user
    """)
    ).scalar_one()
    assert connection.execute(
        text("""
        SELECT NOT EXISTS (
            SELECT FROM pg_class WHERE relowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
        )
    """)
    ).scalar_one()


def read_checks(api: Engine) -> None:
    with api.begin() as connection:
        verify_runtime_role(connection, "veriq_api")
        pid = connection.execute(text("SELECT pg_backend_pid()")).scalar_one()
        assert not tenant_ids(connection)
        sql_denied(connection, "SELECT id FROM users")
        sql_denied(connection, "SELECT * FROM background_jobs")
        sql_denied(connection, "DELETE FROM organization_roles")

    def enter(subject: VerifiedSubject | None, organization: UUID) -> None:
        with tenant_transaction(
            api, subject=subject, requested_organization_id=organization
        ):
            raise AssertionError("Unexpected tenant transaction")

    deny(lambda: enter(None, A))
    deny(lambda: enter(ALICE, B))
    deny(lambda: enter(BOB, A))
    deny(lambda: enter(PLATFORM, A))

    for subject, organization, foreign_member, foreign_role in [
        (ALICE, A, MEMBER_B, ROLE_B),
        (BOB, B, MEMBER_A, ROLE_A),
    ]:
        with tenant_transaction(
            api, subject=subject, requested_organization_id=organization
        ) as access:
            assert (
                access.connection.execute(text("SELECT pg_backend_pid()")).scalar_one()
                == pid
            )
            assert tenant_ids(access.connection) == {organization}
            assert (
                access.connection.execute(
                    text("SELECT id FROM organization_memberships WHERE id = :id"),
                    {"id": foreign_member},
                ).first()
                is None
            )
            assert (
                access.connection.execute(
                    text("SELECT id FROM organization_roles WHERE id = :id"),
                    {"id": foreign_role},
                ).first()
                is None
            )
            access.require(POLICY, TenantResource(organization))
            access.require(OWNER_POLICY, TenantResource(organization, subject.user_id))
            deny(
                partial(
                    access.require,
                    OWNER_POLICY,
                    TenantResource(organization, PLATFORM.user_id),
                )
            )
            deny(lambda: access.require(POLICY, None))
            deny(
                partial(
                    access.require,
                    POLICY,
                    TenantResource(B if organization == A else A),
                )
            )
        with api.begin() as connection:
            assert not tenant_ids(connection)
            assert (
                connection.execute(text("SELECT pg_backend_pid()")).scalar_one() == pid
            )

    try:
        with tenant_transaction(
            api, subject=ALICE, requested_organization_id=A
        ) as access:
            assert tenant_ids(access.connection) == {A}
            raise AccessDenied
    except AccessDenied:
        pass
    with api.begin() as connection:
        assert not tenant_ids(connection)
        assert connection.execute(text("SELECT pg_backend_pid()")).scalar_one() == pid
        set_scope(connection, "invalid-uuid", str(ALICE.user_id))
        assert not tenant_ids(connection)
        set_scope(connection, str(A), "invalid-uuid")
        assert not tenant_ids(connection)
        set_scope(connection, str(B), str(ALICE.user_id))
        assert not tenant_ids(connection)


def write_checks(owner: Engine, api: Engine) -> None:
    # Test-only privilege on a disposable database. Production grants are read-only.
    with owner.begin() as connection:
        connection.execute(
            text("GRANT INSERT, UPDATE, DELETE ON organization_roles TO veriq_api")
        )
    try:
        with tenant_transaction(
            api, subject=ALICE, requested_organization_id=A
        ) as access:
            connection = access.connection
            insert = "INSERT INTO organization_roles VALUES (:org, :id, 'technician')"
            sql_denied(connection, insert, org=B, id=PROBE_ROLE)
            connection.execute(text(insert), {"org": A, "id": PROBE_ROLE})
            sql_denied(
                connection,
                "UPDATE organization_roles SET organization_id = :org WHERE id = :id",
                org=B,
                id=PROBE_ROLE,
            )
            assert (
                connection.execute(
                    text(
                        "UPDATE organization_roles SET code = 'proctor' WHERE id = :id RETURNING id"
                    ),
                    {"id": ROLE_B},
                ).first()
                is None
            )
            assert (
                connection.execute(
                    text("DELETE FROM organization_roles WHERE id = :id RETURNING id"),
                    {"id": ROLE_B},
                ).first()
                is None
            )
            assert (
                connection.execute(
                    text("DELETE FROM organization_roles WHERE id = :id RETURNING id"),
                    {"id": PROBE_ROLE},
                ).scalar_one()
                == PROBE_ROLE
            )
    finally:
        with owner.begin() as connection:
            connection.execute(
                text(
                    "REVOKE INSERT, UPDATE, DELETE ON organization_roles FROM veriq_api"
                )
            )


def revocation_checks(owner: Engine, api: Engine) -> None:
    change_status = text(
        "UPDATE organization_memberships SET status = :status WHERE id = :member"
    )
    with tenant_transaction(
        api, subject=VerifiedSubject(OLD_SUBJECT), requested_organization_id=A
    ) as access:
        deny(lambda: access.require(POLICY, TenantResource(A)))
    with tenant_transaction(api, subject=ALICE, requested_organization_id=A) as access:
        access.require(POLICY, TenantResource(A))
        with owner.begin() as connection:
            connection.execute(change_status, {"status": "revoked", "member": MEMBER_A})
        assert not tenant_ids(access.connection)
        deny(lambda: access.require(POLICY, TenantResource(A)))
        with owner.begin() as connection:
            connection.execute(change_status, {"status": "active", "member": MEMBER_A})
        deny(lambda: access.require(POLICY, TenantResource(A)))


def main() -> None:
    url = database_url()
    assert url.database is not None and url.database.startswith("memberships_test_")
    owner = create_database_engine()
    api = create_engine(
        database_url().set(
            username="veriq_api", password=os.environ["VERIQ_API_DB_PASSWORD"]
        ),
        pool_size=1,
        max_overflow=0,
    )
    worker = create_engine(
        database_url().set(
            username="veriq_worker", password=os.environ["VERIQ_WORKER_DB_PASSWORD"]
        )
    )
    try:
        seed(owner)
        read_checks(api)
        write_checks(owner, api)
        revocation_checks(owner, api)
        with worker.begin() as connection:
            verify_runtime_role(connection, "veriq_worker")
            set_scope(connection, str(A), str(ALICE.user_id))
            sql_denied(connection, "SELECT id FROM organizations")
            sql_denied(
                connection,
                "SELECT public.veriq_active_membership(:org, :subject)",
                org=A,
                subject=str(ALICE.user_id),
            )
            connection.execute(text("SELECT id FROM background_jobs LIMIT 0"))
        print(
            "TEN-01: restricted runtime roles, tenant scope, ABAC, DML, revocation and pool reuse passed."
        )
    finally:
        worker.dispose()
        api.dispose()
        owner.dispose()


if __name__ == "__main__":
    main()
