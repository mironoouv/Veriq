"""Check session revalidation on a migrated, disposable PostgreSQL 17.11."""

from time import monotonic, sleep
from uuid import UUID, uuid4

from academic_catalog_checks import ADMIN, ORG, OTHER, OUTSIDER, role
from academic_group_teacher_schema_checks import fixture
from sqlalchemy import Connection, Engine, text
from veriq.auth_credentials import CredentialVerifier
from veriq.database import create_database_engine
from veriq.sessions import Sessions, SessionToken

Binding = tuple[UUID, UUID, int]
READ = """
    SELECT user_id, organization_id, grant_epoch
    FROM public.auth_sessions
    WHERE id=:id AND token_hash=:digest AND organization_id IS NOT NULL
"""


def read_binding(
    db: Connection, proof: dict[str, object], expected: Binding | None = None
) -> Binding | None:
    query = READ
    params = proof.copy()
    if expected is not None:
        params.update(zip(("account", "tenant", "epoch"), expected, strict=True))
        query += """
            AND user_id=:account AND organization_id=:tenant AND grant_epoch=:epoch
            FOR NO KEY UPDATE NOWAIT
        """
    row = db.execute(text(query), params).tuples().one_or_none()
    if row is None:
        return None
    # Check live server time in a new statement after obtaining the row lock.
    valid = db.execute(
        text("""
        SELECT revoked_at IS NULL AND clock_timestamp() < least(
            idle_expires_at, absolute_expires_at
        ) FROM public.auth_sessions WHERE id=:id AND token_hash=:digest
    """),
        proof,
    ).scalar_one()
    return (row[0], row[1], row[2]) if valid else None


def roster(owner: Engine) -> list[object]:
    with owner.connect() as db:
        return list(
            db.exec_driver_sql("""
            SELECT to_jsonb(m) FROM public.group_memberships AS m ORDER BY organization_id,id
        """).scalars()
        )


def main() -> None:
    owner = create_database_engine()
    store = role("veriq_session_store")
    sessions = Sessions(role("veriq_api"), issuer=role("veriq_session_issuer"))
    verifier = CredentialVerifier(role("veriq_credential_verifier"))
    with owner.connect() as db:
        assert db.exec_driver_sql("SHOW server_version_num").scalar_one() == "170011"
        assert not db.exec_driver_sql(
            "SELECT EXISTS (SELECT FROM organizations)"
        ).scalar_one()
    groups = fixture(owner)
    with owner.begin() as db:
        db.execute(
            text("""
            INSERT INTO public.organization_memberships(id,organization_id,user_id,status)
            VALUES (:id,:org,:account,'active')
        """),
            {"id": uuid4(), "org": OTHER, "account": ADMIN},
        )
        for org, member, group in zip(
            (ORG, OTHER), (ADMIN, OUTSIDER), groups, strict=True
        ):
            db.execute(
                text("""
                INSERT INTO public.group_memberships
                    (organization_id,id,group_id,membership_id,start_at)
                VALUES (:org,:id,:group,:member,clock_timestamp())
            """),
                {"org": org, "id": uuid4(), "group": group, "member": member},
            )
    before = roster(owner)
    assert len(before) == 2

    def issue() -> SessionToken:
        return sessions.issue(
            verifier.confirm(ADMIN, 1, mfa_level=1, organization_id=ORG)
        )

    def proof_for(token: SessionToken) -> dict[str, object]:
        gate = token._gate(sessions.policy)
        return {"id": gate.session_id, "digest": gate.digest}

    token = issue()
    proof = proof_for(token)
    with store.begin() as db:
        assert (
            db.exec_driver_sql("SELECT current_user").scalar_one()
            == "veriq_session_store"
        )
        db.exec_driver_sql("SET LOCAL statement_timeout = '5s'")
        first = read_binding(db, proof)
        assert first is not None and first[:2] == (ADMIN, ORG)
        assert read_binding(db, proof, first) == first

    with store.begin() as db:
        db.exec_driver_sql("SET LOCAL statement_timeout = '5s'")
        assert read_binding(db, proof) == first
        replacement = sessions.rotate(token, organization_id=OTHER)
        rotated = read_binding(db, proof_for(replacement))
        assert rotated is not None and rotated[:2] == (ADMIN, OTHER)
        assert read_binding(db, proof, first) is None
        assert roster(owner) == before

    expiring = proof_for(issue())
    with owner.begin() as db:
        deadline = db.execute(
            text("""
            UPDATE public.auth_sessions SET idle_expires_at=clock_timestamp()+interval '2s'
            WHERE id=:id RETURNING idle_expires_at
        """),
            {"id": expiring["id"]},
        ).scalar_one()
    with store.begin() as db:
        db.exec_driver_sql("SET LOCAL statement_timeout = '5s'")
        initial = read_binding(db, expiring)
        assert initial is not None and initial[:2] == (ADMIN, ORG)
        assert (
            db.exec_driver_sql("SELECT transaction_timestamp()").scalar_one() < deadline
        )
        stop = monotonic() + 5
        while db.exec_driver_sql("SELECT clock_timestamp()").scalar_one() < deadline:
            assert monotonic() < stop, "Server expiry deadline was not reached"
            sleep(0.02)
        assert read_binding(db, expiring, initial) is None
        assert roster(owner) == before
    print(
        "Session binding, tenant rotation, server-clock expiry and unchanged A/B roster passed"
    )


if __name__ == "__main__":
    main()
