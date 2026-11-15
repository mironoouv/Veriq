"""Test the transfer write sequence on a newly migrated disposable database."""

from datetime import datetime
from uuid import UUID, uuid4

from academic_catalog_checks import ADMIN, ORG, OTHER, OUTSIDER, role
from academic_group_teacher_schema_checks import fixture
from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import DBAPIError
from veriq.academic_catalog import AcademicCatalog, CatalogInput, CatalogKind
from veriq.auth_credentials import CredentialVerifier
from veriq.database import create_database_engine
from veriq.sessions import Sessions

INSERT = text("""
    INSERT INTO group_memberships
        (organization_id,id,group_id,membership_id,start_at)
    VALUES (:org,:id,:group_id,:member,:tick)
""")


class ClosedSource(Exception):
    """The source interval was already closed."""


def snapshot(db: Connection) -> tuple[tuple[object, ...], ...]:
    return tuple(
        tuple(
            db.exec_driver_sql(
                f"SELECT to_jsonb(t) FROM public.{table} t ORDER BY organization_id,id"
            ).scalars()
        )
        for table in ("group_memberships", "fixture_transfer_audit")
    )


def transfer(
    db: Connection,
    source: UUID,
    destination: UUID,
    request: UUID,
    *,
    reject_audit: bool = False,
) -> tuple[UUID, datetime]:
    tick = db.exec_driver_sql("SELECT clock_timestamp()").scalar_one()
    closed = db.execute(
        text("""
            UPDATE group_memberships SET end_at=:tick
            WHERE organization_id=:org AND id=:source AND end_at IS NULL
            RETURNING membership_id
        """),
        {"org": ORG, "source": source, "tick": tick},
    ).scalar_one_or_none()
    if closed is None:
        raise ClosedSource
    target = uuid4()
    db.execute(
        INSERT,
        {
            "org": ORG,
            "id": target,
            "group_id": destination,
            "member": closed,
            "tick": tick,
        },
    )
    db.exec_driver_sql(
        """INSERT INTO fixture_transfer_audit
           (organization_id,id,source_id,target_id,occurred_at,accepted)
           VALUES (%s,%s,%s,%s,%s,%s)""",
        (ORG, request, source, target, tick, not reject_audit),
    )
    return target, tick


def verify_failure(
    owner: Engine,
    observer: Connection,
    source: UUID,
    destination: UUID,
    request: UUID,
    expected: str,
    *,
    reject_audit: bool = False,
) -> None:
    before = snapshot(observer)
    try:
        with owner.begin() as db:
            transfer(db, source, destination, request, reject_audit=reject_audit)
    except ClosedSource:
        assert expected == "closed"
    except DBAPIError as exc:
        assert getattr(exc.orig, "sqlstate", None) == expected
        assert getattr(exc.orig.diag, "constraint_name", None) == (
            "fixture_audit_accepts" if reject_audit else "group_memberships_no_overlap"
        )
    else:
        raise AssertionError("Transfer unexpectedly committed")
    assert snapshot(observer) == before


def main() -> None:
    owner = create_database_engine()
    with owner.connect() as db:
        assert db.exec_driver_sql("SHOW server_version_num").scalar_one() == "170011"
        assert (
            db.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one()
            == "0025"
        )
        assert not db.exec_driver_sql(
            "SELECT EXISTS (SELECT FROM organizations)"
        ).scalar_one()
    source_group, other_group = fixture(owner)
    destination = uuid4()
    sessions = Sessions(role("veriq_api"), issuer=role("veriq_session_issuer"))
    actor = sessions.issue(
        CredentialVerifier(role("veriq_credential_verifier")).confirm(
            ADMIN, 1, mfa_level=1, organization_id=ORG
        )
    )
    AcademicCatalog(sessions).write(
        actor,
        ORG,
        CatalogKind.GROUPS,
        destination,
        CatalogInput(title="Transfer destination"),
        uuid4(),
    )
    source, other, rollback_source, request = (uuid4() for _ in range(4))
    with owner.begin() as db:
        db.exec_driver_sql("""
            CREATE TABLE fixture_transfer_audit (
                organization_id uuid NOT NULL,
                id uuid PRIMARY KEY,
                source_id uuid NOT NULL,
                target_id uuid NOT NULL,
                occurred_at timestamptz NOT NULL,
                accepted boolean NOT NULL CONSTRAINT fixture_audit_accepts CHECK (accepted)
            )
        """)
        for org, interval, group, member in (
            (ORG, source, source_group, ADMIN),
            (OTHER, other, other_group, OUTSIDER),
        ):
            db.execute(
                INSERT,
                {
                    "org": org,
                    "id": interval,
                    "group_id": group,
                    "member": member,
                    "tick": db.exec_driver_sql(
                        "SELECT clock_timestamp()-interval '1 day'"
                    ).scalar_one(),
                },
            )

    with owner.connect() as observer:
        before = snapshot(observer)
        with owner.begin() as db:
            target, tick = transfer(db, source, destination, request)
            assert snapshot(observer) == before
        after = snapshot(observer)
        assert len(after[0]) == len(before[0]) + 1
        outside = observer.exec_driver_sql(
            "SELECT to_jsonb(t) FROM group_memberships t WHERE organization_id=%s",
            (OTHER,),
        ).scalar_one()
        assert outside in before[0]
        assert observer.exec_driver_sql(
            """
            SELECT s.end_at,t.start_at,a.occurred_at,t.group_id,t.membership_id
            FROM fixture_transfer_audit a
            JOIN group_memberships s ON (s.organization_id,s.id)=(a.organization_id,a.source_id)
            JOIN group_memberships t ON (t.organization_id,t.id)=(a.organization_id,a.target_id)
            WHERE a.organization_id=%s AND a.id=%s AND s.id=%s AND t.id=%s
        """,
            (ORG, request, source, target),
        ).one() == (tick, tick, tick, destination, ADMIN)
        assert len(after[1]) == 1
        verify_failure(owner, observer, source, destination, request, "closed")

        with owner.begin() as db:
            db.execute(
                INSERT,
                {
                    "org": ORG,
                    "id": rollback_source,
                    "group_id": source_group,
                    "member": ADMIN,
                    "tick": tick,
                },
            )
        verify_failure(owner, observer, rollback_source, destination, uuid4(), "23P01")
        # The original group is free for the interval now open at the destination
        # only after ending the rollback fixture.
        with owner.begin() as db:
            db.exec_driver_sql(
                "UPDATE group_memberships SET end_at=clock_timestamp() WHERE organization_id=%s AND id=%s",
                (ORG, rollback_source),
            )
        verify_failure(
            owner, observer, target, source_group, uuid4(), "23514", reject_audit=True
        )
    owner.dispose()
    print("Transfer commit, replay, overlap and forced audit rollback passed")


if __name__ == "__main__":
    main()
