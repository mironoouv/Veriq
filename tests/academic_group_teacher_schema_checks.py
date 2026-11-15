"""Apply 0024 on an empty disposable database. Run separately with clean or upgrade."""

import argparse
from uuid import UUID, uuid4

from academic_catalog_checks import ADMIN, ORG, OTHER, OUTSIDER, role, seed
from alembic import command
from alembic.config import Config
from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import DBAPIError
from veriq.academic_catalog import AcademicCatalog, CatalogInput, CatalogKind
from veriq.auth_credentials import CredentialVerifier
from veriq.database import create_database_engine
from veriq.sessions import Sessions

TABLE = "public.academic_group_teacher_assignments"


def snapshot(db: Connection) -> tuple[object, ...]:
    return tuple(
        tuple(
            db.exec_driver_sql(
                f"SELECT to_jsonb(t) FROM public.{table} t ORDER BY organization_id,id"
            ).scalars()
        )
        for table in ("courses", "study_groups", "academic_catalog_events")
    )


def fixture(owner: Engine) -> tuple[UUID, UUID]:
    seed(owner)
    with owner.begin() as db:
        db.exec_driver_sql("""
            INSERT INTO organization_role_permissions(organization_id,role_id,permission_code)
            SELECT organization_id,id,'academic.catalog.manage'
            FROM organization_roles WHERE code='org_admin' ON CONFLICT DO NOTHING
        """)
        db.exec_driver_sql("""
            INSERT INTO organization_role_permissions(organization_id,role_id,permission_code)
            SELECT organization_id,id,'academic.catalog.read'
            FROM organization_roles WHERE code='org_admin' ON CONFLICT DO NOTHING
        """)
    sessions = Sessions(role("veriq_api"), issuer=role("veriq_session_issuer"))
    verifier = CredentialVerifier(role("veriq_credential_verifier"))
    groups = (uuid4(), uuid4())
    for org, user, group in zip((ORG, OTHER), (ADMIN, OUTSIDER), groups, strict=True):
        actor = sessions.issue(
            verifier.confirm(user, 1, mfa_level=1, organization_id=org)
        )
        for kind, item in ((CatalogKind.GROUPS, group), (CatalogKind.COURSES, uuid4())):
            AcademicCatalog(sessions).write(
                actor, org, kind, item, CatalogInput(title="Schema fixture"), uuid4()
            )
    return groups


def expect_state(db: Connection, statement: str, state: str, **params: object) -> None:
    try:
        with db.begin_nested():
            db.execute(text(statement), params)
    except DBAPIError as exc:
        assert getattr(exc.orig, "sqlstate", None) == state
    else:
        raise AssertionError(f"Expected SQLSTATE {state}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("clean", "upgrade"))
    mode = parser.parse_args().mode
    owner = create_database_engine()
    with owner.connect() as db:
        assert db.scalar(text("SELECT to_regclass('public.alembic_version')")) is None
    config = Config("alembic.ini")
    if mode == "upgrade":
        command.upgrade(config, "0023")
        a, b = fixture(owner)
        with owner.connect() as db:
            before = snapshot(db)
        command.upgrade(config, "0024")
        with owner.connect() as db:
            assert snapshot(db) == before
    else:
        command.upgrade(config, "0024")
        a, b = fixture(owner)

    insert = f"""INSERT INTO {TABLE} (organization_id,id,group_id,membership_id,grant_epoch)
        SELECT :org,:id,:group_id,:member,grant_epoch
        FROM public.organization_memberships WHERE id=:member"""
    args = {"org": ORG, "id": uuid4(), "group_id": a, "member": ADMIN}
    with owner.begin() as db:
        assert db.scalar(text("SELECT version_num FROM alembic_version")) == "0024"
        assert db.execute(
            text("""
            SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid=to_regclass(:name)
        """),
            {"name": TABLE},
        ).one() == (True, True)
        assert db.execute(text(insert), args).rowcount == 1
        expect_state(db, insert, "23503", **(args | {"id": uuid4(), "group_id": b}))
        expect_state(
            db, insert, "23503", **(args | {"id": uuid4(), "member": OUTSIDER})
        )
        expect_state(db, insert, "23505", **(args | {"id": uuid4()}))
        db.execute(
            text(f"UPDATE {TABLE} SET revoked_at=clock_timestamp() WHERE id=:id"), args
        )
        assert db.execute(text(insert), args | {"id": uuid4()}).rowcount == 1
        assert (
            db.scalar(
                text(f"SELECT count(*) FROM {TABLE} WHERE revoked_at IS NOT NULL")
            )
            == 1
        )

    with role("veriq_api").begin() as db:
        assert db.scalar(text("SELECT current_user")) == "veriq_api"
        expect_state(db, f"SELECT * FROM {TABLE}", "42501")
        expect_state(
            db,
            f"""INSERT INTO {TABLE}
            (organization_id,id,group_id,membership_id,grant_epoch)
            VALUES (:org,:id,:group_id,:member,0)""",
            "42501",
            **args,
        )
        expect_state(db, f"UPDATE {TABLE} SET revoked_at=now()", "42501")
        expect_state(db, f"DELETE FROM {TABLE}", "42501")
    print(f"0024 {mode}: catalog, RLS, tenant FKs, history and runtime denials passed")


if __name__ == "__main__":
    main()
