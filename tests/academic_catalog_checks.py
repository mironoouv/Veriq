"""Catalog upgrade, runtime RLS, optimistic editing and authority races."""

import sys
from concurrent.futures import ThreadPoolExecutor
from uuid import UUID, uuid4

from sqlalchemy import Connection, Engine, event, text
from sqlalchemy.exc import DBAPIError
from veriq.academic_catalog import (
    AcademicCatalog,
    CatalogArchive,
    CatalogConflict,
    CatalogEdit,
    CatalogInput,
    CatalogKind,
    CatalogPage,
    CatalogRestore,
)
from veriq.auth_credentials import CredentialVerifier
from veriq.database import create_database_engine
from veriq.sessions import Sessions
from veriq.tenant_access import AccessDenied

ORG, OTHER, ADMIN, OUTSIDER = (UUID(int=12300 + i) for i in range(4))


def role(name: str) -> Engine:
    engine = create_database_engine()

    @event.listens_for(engine, "begin")
    def assume(connection: Connection) -> None:
        connection.exec_driver_sql(f"SET LOCAL ROLE {name}")

    return engine


def seed(owner: Engine) -> None:
    with owner.begin() as conn:
        for org, user in ((ORG, ADMIN), (OTHER, OUTSIDER)):
            conn.execute(
                text("""
                INSERT INTO organizations(id,slug,display_name,timezone,status)
                VALUES (:org,:slug,'Catalog fixture','UTC','active')
            """),
                {"org": org, "slug": org.hex},
            )
            conn.execute(
                text("""
                INSERT INTO users(id,email_normalized,email_verified_at,password_hash)
                VALUES (:user,:mail,now(),'fixture-only')
            """),
                {"user": user, "mail": f"{user.hex}@example.invalid"},
            )
            conn.execute(
                text("""
                INSERT INTO organization_memberships(id,organization_id,user_id,status)
                VALUES (:user,:org,:user,'active')
            """),
                {"org": org, "user": user},
            )
            conn.execute(
                text("""
                INSERT INTO organization_roles VALUES (:org,:user,'org_admin');
            """),
                {"org": org, "user": user},
            )
            conn.execute(
                text("""
                INSERT INTO membership_roles(organization_id,membership_id,role_id)
                VALUES (:org,:user,:user)
            """),
                {"org": org, "user": user},
            )

    api = role("veriq_api")
    Sessions(api, issuer=role("veriq_session_issuer")).issue(
        CredentialVerifier(role("veriq_credential_verifier")).confirm(
            ADMIN, 1, mfa_level=1, organization_id=ORG
        )
    )


def run(owner: Engine, api: Engine) -> None:
    with owner.begin() as conn:
        assert (
            conn.execute(
                text(
                    "SELECT count(*) FROM auth_sessions WHERE user_id=:user AND organization_id=:org AND revoked_at IS NULL"
                ),
                {"user": ADMIN, "org": ORG},
            ).scalar_one()
            == 1
        )
    sessions = Sessions(api, issuer=role("veriq_session_issuer"))
    verifier = CredentialVerifier(role("veriq_credential_verifier"))
    actor = sessions.issue(verifier.confirm(ADMIN, 1, mfa_level=1, organization_id=ORG))
    other_actor = sessions.issue(
        verifier.confirm(OUTSIDER, 1, mfa_level=1, organization_id=OTHER)
    )
    catalog = AcademicCatalog(sessions)
    item = uuid4()
    entry = CatalogInput(title=" Mathematics ", description="Fixture course")
    course = CatalogKind.COURSES
    assert (
        catalog.write(actor, ORG, course, item, entry, uuid4()).title == "Mathematics"
    )
    assert catalog.write(actor, ORG, course, item, entry, uuid4()).version == 1
    catalog.write(
        other_actor, OTHER, course, item, CatalogInput(title="Other tenant"), uuid4()
    )
    catalog.write(
        actor, ORG, CatalogKind.GROUPS, item, CatalogInput(title="Group A"), uuid4()
    )
    page = catalog.read(actor, ORG, course, None, False, "math", 1)
    assert (
        isinstance(page, CatalogPage) and page.total == 1 and page.items[0].id == item
    )
    assert catalog.read(actor, ORG, course, item, False, "", 1).title == "Mathematics"
    with sessions.tenant(actor) as access:
        assert (
            access.connection.execute(
                text("SELECT count(*) FROM courses WHERE organization_id=:org"),
                {"org": OTHER},
            ).scalar_one()
            == 0
        )
        assert (
            access.connection.execute(
                text("UPDATE courses SET title='Forbidden' WHERE organization_id=:org"),
                {"org": OTHER},
            ).rowcount
            == 0
        )
    try:
        catalog.read(actor, OTHER, course, item, False, "", 1)
    except AccessDenied:
        pass
    else:
        raise AssertionError("Foreign tenant read accepted")
    try:
        catalog.write(
            actor,
            OTHER,
            course,
            item,
            CatalogEdit(title="Forbidden", version=1),
            uuid4(),
        )
    except AccessDenied:
        pass
    else:
        raise AssertionError("Foreign tenant write accepted")
    with api.begin() as conn:
        assert conn.execute(text("SELECT count(*) FROM courses")).scalar_one() == 0
    try:
        with api.begin() as conn:
            conn.execute(
                text("""
                INSERT INTO courses(organization_id,id,title,create_digest)
                VALUES (:org,:id,'Forbidden',decode(repeat('00',32),'hex'))
            """),
                {"org": OTHER, "id": uuid4()},
            )
    except DBAPIError as exc:
        assert exc.orig.sqlstate == "42501"
    else:
        raise AssertionError("Write without tenant context accepted")

    def edit(index: int) -> str:
        try:
            catalog.write(
                actor,
                ORG,
                course,
                item,
                CatalogEdit(title=f"Revision {index}", version=1),
                uuid4(),
            )
        except CatalogConflict:
            return "conflict"
        return "updated"

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(edit, range(2))) == ["conflict", "updated"]
    archive = CatalogArchive(version=2)
    assert (
        catalog.write(actor, ORG, course, item, archive, uuid4()).status == "archived"
    )
    assert catalog.write(actor, ORG, course, item, archive, uuid4()).version == 3
    archive_page = catalog.read(actor, ORG, course, None, True, "", 1)
    assert isinstance(archive_page, CatalogPage) and archive_page.total == 1
    with owner.begin() as conn:
        assert (
            conn.execute(
                text("""
            SELECT count(*) FROM academic_catalog_events WHERE organization_id=:org AND course_id=:id
        """),
                {"org": ORG, "id": item},
            ).scalar_one()
            == 3
        )
        assert (
            conn.execute(
                text("SELECT count(*) FROM users WHERE id IN (:one,:two)"),
                {"one": ADMIN, "two": OUTSIDER},
            ).scalar_one()
            == 2
        )

    def check_restore(kind: CatalogKind) -> None:
        restored_id = uuid4()
        original = catalog.write(actor, ORG, kind, restored_id, entry, uuid4())
        archived = catalog.write(
            actor,
            ORG,
            kind,
            restored_id,
            CatalogArchive(version=original.version),
            uuid4(),
        )

        with owner.begin() as conn:
            conn.execute(
                text(
                    "ALTER TABLE public.academic_catalog_events ADD CONSTRAINT test_reject_restore "
                    "CHECK (action <> 'restore') NOT VALID"
                )
            )
        try:
            catalog.write(
                actor,
                ORG,
                kind,
                restored_id,
                CatalogRestore(version=archived.version),
                uuid4(),
            )
        except DBAPIError as exc:
            assert exc.orig.sqlstate == "23514"
        else:
            raise AssertionError("Restore committed despite audit failure")
        finally:
            with owner.begin() as conn:
                conn.execute(
                    text(
                        "ALTER TABLE public.academic_catalog_events DROP CONSTRAINT test_reject_restore"
                    )
                )
        assert catalog.read(actor, ORG, kind, restored_id, True, "", 1) == archived

        def restore(_: int) -> str:
            try:
                result = catalog.write(
                    actor,
                    ORG,
                    kind,
                    restored_id,
                    CatalogRestore(version=archived.version),
                    uuid4(),
                )
            except CatalogConflict:
                return "conflict"
            assert result.id == original.id and result.status == "active"
            assert result.version == archived.version + 1
            return "restored"

        with ThreadPoolExecutor(max_workers=2) as pool:
            assert sorted(pool.map(restore, range(2))) == ["conflict", "restored"]

        def transition(command: CatalogArchive) -> str:
            try:
                return catalog.write(
                    actor, ORG, kind, restored_id, command, uuid4()
                ).status
            except CatalogConflict:
                return "conflict"

        with ThreadPoolExecutor(max_workers=2) as pool:
            archive_again = pool.submit(
                transition, CatalogArchive(version=archived.version + 1)
            )
            stale_restore = pool.submit(
                transition, CatalogRestore(version=archived.version)
            )
            assert archive_again.result() == "archived"
            assert stale_restore.result() == "conflict"
        current = catalog.read(actor, ORG, kind, restored_id, True, "", 1)
        assert current.status == "archived" and current.version == archived.version + 2
        assert transition(CatalogArchive(version=archived.version + 1)) == "archived"

        with owner.begin() as conn:
            actions = (
                conn.execute(
                    text(
                        "SELECT action FROM academic_catalog_events "
                        "WHERE organization_id=:org AND (course_id=:id OR group_id=:id)"
                    ),
                    {"org": ORG, "id": restored_id},
                )
                .scalars()
                .all()
            )
            assert sorted(actions) == ["archive", "archive", "create", "restore"]

    for kind in CatalogKind:
        check_restore(kind)

    with ThreadPoolExecutor(max_workers=1) as pool:
        with owner.begin() as conn:
            conn.execute(
                text("""
                DELETE FROM organization_role_permissions
                WHERE organization_id=:org AND role_id=:actor AND permission_code='academic.catalog.manage'
            """),
                {"org": ORG, "actor": ADMIN},
            )
            write = pool.submit(
                catalog.write,
                actor,
                ORG,
                course,
                item,
                CatalogRestore(version=3),
                uuid4(),
            )
        try:
            write.result()
        except AccessDenied:
            pass
        else:
            raise AssertionError("Revoked permission accepted")
    with owner.begin() as conn:
        conn.execute(
            text("""
            DELETE FROM organization_role_permissions
            WHERE organization_id=:org AND role_id=:actor AND permission_code='academic.catalog.archive'
        """),
            {"org": ORG, "actor": ADMIN},
        )
    try:
        catalog.read(actor, ORG, course, item, False, "", 1)
    except AccessDenied:
        pass
    else:
        raise AssertionError("Archived record visible without archive grant")
    print(
        "Academic catalog: tenant RLS, upgrades, optimistic edit, archive replay and revocation race passed."
    )


if __name__ == "__main__":
    owner = create_database_engine()
    if sys.argv[1:] == ["seed"]:
        seed(owner)
    elif sys.argv[1:] == ["after-downgrade"]:
        with owner.connect() as conn:
            assert (
                conn.execute(
                    text(
                        "SELECT count(*) FROM public.academic_catalog_events WHERE action='restore'"
                    )
                ).scalar_one()
                == 2
            )
            assert (
                conn.execute(
                    text(
                        "SELECT count(*) FROM pg_policies WHERE policyname='catalog_restore'"
                    )
                ).scalar_one()
                == 2
            )
    else:
        run(owner, role("veriq_api"))
