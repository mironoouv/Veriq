"""PostgreSQL onboarding and upgrade tests under the actual runtime roles."""

import secrets
import sys
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from uuid import NAMESPACE_URL, UUID, uuid5

from sqlalchemy import Connection, Engine, event, text
from sqlalchemy.exc import DBAPIError
from veriq.auth_audit import RequestContext
from veriq.auth_credentials import CredentialVerifier
from veriq.database import create_database_engine
from veriq.mfa import Mfa
from veriq.mfa_crypto import FactorKeys
from veriq.organization_joining import JoinCommand, OrganizationJoining
from veriq.registration_policy import HASHER
from veriq.sessions import Sessions, SessionToken
from veriq.tenant_access import AccessDenied


def fixture(label: str) -> UUID:
    return uuid5(NAMESPACE_URL, f"https://example.invalid/veriq-joining/{label}")


PASSWORD_HASH = HASHER.hash("synthetic organization joining fixture")
ORG, OTHER = fixture("org"), fixture("other")
ADMIN, APPLICANT, INVITEE, SUSPENDED, REVOKED, UNVERIFIED = (
    fixture(name)
    for name in ("admin", "applicant", "invitee", "suspended", "revoked", "unverified")
)


def role(name: str) -> Engine:
    engine = create_database_engine()

    @event.listens_for(engine, "begin")
    def assume(connection: Connection) -> None:
        connection.exec_driver_sql(f"SET LOCAL ROLE {name}")

    return engine


def denied(operation: Callable[[], object]) -> None:
    try:
        operation()
    except AccessDenied:
        return
    raise AssertionError("Expected AccessDenied")


def session(
    api: Engine, user: UUID, tenant: UUID | None = None, level: int = 0
) -> SessionToken:
    verifier = CredentialVerifier(role("veriq_credential_verifier"))
    return Sessions(api, issuer=role("veriq_session_issuer")).issue(
        verifier.confirm(user, 1, mfa_level=level, organization_id=tenant)
    )


def seed(owner: Engine, api: Engine) -> None:
    with owner.begin() as conn:
        for tenant in (ORG, OTHER):
            conn.execute(
                text("""
                INSERT INTO organizations (id,slug,display_name,timezone,status)
                VALUES (:id,:slug,'Joining test','UTC','active')
            """),
                {"id": tenant, "slug": tenant.hex},
            )
        for user in (ADMIN, APPLICANT, INVITEE, SUSPENDED, REVOKED, UNVERIFIED):
            conn.execute(
                text("""
                INSERT INTO users(id,email_normalized,email_verified_at,password_hash)
                VALUES (:id,:mail,CASE WHEN :verified THEN now() END,:password_hash)
            """),
                {
                    "id": user,
                    "mail": f"{user.hex}@example.invalid",
                    "verified": user != UNVERIFIED,
                    "password_hash": PASSWORD_HASH,
                },
            )
        for user, state in (
            (ADMIN, "active"),
            (SUSPENDED, "suspended"),
            (REVOKED, "revoked"),
        ):
            conn.execute(
                text("""
                INSERT INTO organization_memberships(id,user_id,organization_id,status)
                VALUES (:id,:user,:org,:state)
            """),
                {"id": user, "user": user, "org": ORG, "state": state},
            )
        conn.execute(
            text("INSERT INTO organization_roles VALUES (:org,:id,'org_admin')"),
            {"org": ORG, "id": ADMIN},
        )
        conn.execute(
            text("""
            INSERT INTO membership_roles (organization_id,membership_id,role_id)
            VALUES (:org,:id,:id)
        """),
            {"org": ORG, "id": ADMIN},
        )
    Mfa(
        role("veriq_mfa_verifier"),
        Sessions(api),
        FactorKeys("fixture", {"fixture": secrets.token_bytes(32)}),
    ).prepare_enrollment(ADMIN, RequestContext.new())
    token = session(api, ADMIN, ORG, 1)
    session_id = token._gate(Sessions(api).policy).session_id
    with owner.begin() as conn:
        conn.execute(
            text("""
            INSERT INTO mfa_session_assurance(session_id,purpose,verified_at)
            VALUES (:id,'sensitive',clock_timestamp())
        """),
            {"id": session_id},
        )


def run(owner: Engine, api: Engine) -> None:
    with owner.begin() as conn:
        assert (
            conn.execute(
                text("SELECT count(*) FROM auth_sessions WHERE user_id=:id"),
                {"id": ADMIN},
            ).scalar_one()
            == 1
        )
        assert (
            conn.execute(
                text("""
            SELECT count(*) FROM mfa_session_assurance a JOIN auth_sessions s ON s.id=a.session_id
            WHERE s.user_id=:id AND a.purpose='sensitive'
        """),
                {"id": ADMIN},
            ).scalar_one()
            == 1
        )
        assert (
            conn.execute(
                text("SELECT count(*) FROM membership_roles WHERE membership_id=:id"),
                {"id": ADMIN},
            ).scalar_one()
            == 1
        )
        assert (
            conn.execute(
                text("SELECT count(*) FROM mfa_factors WHERE user_id=:id"),
                {"id": ADMIN},
            ).scalar_one()
            == 1
        )
    service = OrganizationJoining(api)
    staff = session(api, ADMIN, ORG, 1)
    applicant = session(api, APPLICANT)
    invitee = session(api, INVITEE)
    suspended = session(api, SUSPENDED)
    revoked = session(api, REVOKED)
    unverified = session(api, UNVERIFIED)
    with owner.begin() as conn:
        conn.execute(
            text("""
            INSERT INTO mfa_session_assurance(session_id,purpose,verified_at)
            VALUES (:id,'sensitive',clock_timestamp())
        """),
            {"id": staff._gate(service.policy).session_id},
        )

    def command(
        token: SessionToken, action: str, org: UUID = ORG, **fields: object
    ) -> dict[str, str]:
        return service.execute(
            org,
            token,
            JoinCommand.model_validate({"action": action, **fields}),
            RequestContext.new(),
        )

    denied(lambda: command(applicant, "apply"))
    denied(lambda: command(applicant, "issue_code", quota=1))
    denied(lambda: command(staff, "issue_code", OTHER, quota=1))
    denied(lambda: command(session(api, ADMIN, ORG, 1), "issue_code", quota=1))
    denied(
        lambda: command(staff, "issue_invite", recipient_id=UNVERIFIED, enabled=True)
    )
    try:
        command(applicant, "apply", role="org_admin")
    except ValueError:
        pass
    else:
        raise AssertionError("Role field accepted")
    assert command(staff, "set_intake", enabled=True)["status"] == "enabled"
    denied(lambda: command(unverified, "apply"))
    with ThreadPoolExecutor(max_workers=2) as pool:
        left, right = list(pool.map(lambda _: command(applicant, "apply"), range(2)))
    assert left == right and left["status"] == "pending"
    assert command(staff, "approve", object_id=left["request_id"])["status"] == "active"
    denied(lambda: command(staff, "approve", object_id=left["request_id"]))

    expired = command(staff, "issue_invite", recipient_id=INVITEE, enabled=True)
    with owner.begin() as conn:
        conn.execute(
            text("""
            UPDATE invites SET created_at=now()-interval '2 hours',expires_at=now()-interval '1 hour'
            WHERE id=:id
        """),
            {"id": expired["object_id"]},
        )
    denied(
        lambda: command(
            invitee,
            "redeem_invite",
            object_id=expired["object_id"],
            secret=expired["secret"],
        )
    )
    invite = command(staff, "issue_invite", recipient_id=INVITEE, enabled=True)

    def redeem(token: SessionToken, org: UUID = ORG) -> dict[str, str]:
        return command(
            token,
            "redeem_invite",
            org,
            object_id=invite["object_id"],
            secret=invite["secret"],
        )

    denied(lambda: redeem(applicant))
    denied(lambda: redeem(invitee, OTHER))
    denied(
        lambda: command(
            invitee,
            "redeem_invite",
            object_id=fixture("wrong-invite"),
            secret=invite["secret"],
        )
    )

    def race(_: int) -> str:
        try:
            return redeem(invitee)["status"]
        except AccessDenied:
            return "denied"

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(race, range(2))) == ["active", "denied"]

    for user, token in ((SUSPENDED, suspended), (REVOKED, revoked)):
        invitation = command(staff, "issue_invite", recipient_id=user, enabled=True)
        denied(
            lambda token=token, invitation=invitation: command(
                token,
                "redeem_invite",
                object_id=invitation["object_id"],
                secret=invitation["secret"],
            )
        )

    invitation = command(staff, "issue_invite", recipient_id=INVITEE, enabled=True)
    command(staff, "revoke_invite", object_id=invitation["object_id"])
    denied(
        lambda: command(
            invitee,
            "redeem_invite",
            object_id=invitation["object_id"],
            secret=invitation["secret"],
        )
    )
    code = command(staff, "issue_code", quota=1)
    # Use a second tenant for the same account without changing the first membership.
    with owner.begin() as conn:
        conn.execute(
            text("INSERT INTO organization_join_intake VALUES (:org,true)"),
            {"org": OTHER},
        )
    assert command(applicant, "apply", OTHER)["status"] == "pending"
    assert command(applicant, "status")["status"] == "active"
    assert command(applicant, "status", OTHER)["status"] == "pending"

    code_to_revoke = command(staff, "issue_code", quota=1)
    assert (
        command(staff, "revoke_code", object_id=code_to_revoke["object_id"])["status"]
        == "revoked"
    )
    denied(
        lambda: command(
            applicant,
            "redeem_code",
            object_id=code_to_revoke["object_id"],
            secret=code_to_revoke["secret"],
        )
    )
    new_user = fixture("new-applicant")
    with owner.begin() as conn:
        conn.execute(
            text("""
            INSERT INTO users(id,email_normalized,email_verified_at,password_hash) VALUES (:id,:mail,now(),:password_hash)
        """),
            {
                "id": new_user,
                "mail": "joining-code@example.invalid",
                "password_hash": PASSWORD_HASH,
            },
        )
    code_token = session(api, new_user)
    via_code = command(
        code_token, "redeem_code", object_id=code["object_id"], secret=code["secret"]
    )
    assert via_code["status"] == "pending"
    denied(
        lambda: command(
            code_token,
            "redeem_code",
            object_id=code["object_id"],
            secret=code["secret"],
        )
    )
    assert (
        command(staff, "reject", object_id=via_code["request_id"])["status"]
        == "revoked"
    )
    denied(lambda: command(code_token, "apply"))
    review_target = fixture("last-applicant")
    with owner.begin() as conn:
        conn.execute(
            text("""
            INSERT INTO users(id,email_normalized,email_verified_at,password_hash)
            VALUES (:id,'joining-last@example.invalid',now(),:hash)
        """),
            {"id": review_target, "hash": PASSWORD_HASH},
        )
    pending = command(session(api, review_target), "apply")
    with ThreadPoolExecutor(max_workers=1) as pool:
        with owner.begin() as conn:
            conn.execute(
                text("DELETE FROM membership_roles WHERE membership_id=:id"),
                {"id": ADMIN},
            )
            review = pool.submit(
                command, staff, "approve", object_id=pending["request_id"]
            )
        denied(review.result)
    denied(lambda: command(staff, "revoke_code", object_id=code["object_id"]))

    def constraint(sql: str, state: str, **values: object) -> None:
        try:
            with owner.begin() as conn:
                conn.execute(text(sql), values)
        except DBAPIError as error:
            assert error.orig.sqlstate == state
        else:
            raise AssertionError("Expected database constraint")

    constraint(
        "UPDATE group_join_codes SET uses=max_uses+1 WHERE id=:id",
        "23514",
        id=code["object_id"],
    )
    constraint(
        "UPDATE invites SET expires_at=created_at+interval '73 hours' WHERE id=:id",
        "23514",
        id=invite["object_id"],
    )
    constraint(
        """INSERT INTO join_requests(organization_id,id,membership_id,user_id)
        SELECT :foreign_org,:id,membership_id,user_id FROM join_requests WHERE id=:existing""",
        "23503",
        foreign_org=OTHER,
        id=fixture("cross-tenant"),
        existing=pending["request_id"],
    )
    constraint(
        """INSERT INTO join_requests(organization_id,id,membership_id,user_id)
        SELECT organization_id,:id,membership_id,user_id FROM join_requests WHERE id=:existing""",
        "23505",
        id=fixture("duplicate-pending"),
        existing=pending["request_id"],
    )

    for table in ("invites", "join_requests", "join_audit_events", "group_join_codes"):
        for engine in (api, role("veriq_worker")):
            try:
                with engine.begin() as conn:
                    conn.exec_driver_sql(f"SELECT 1 FROM {table}")
            except DBAPIError as error:
                assert error.orig.sqlstate == "42501"
            else:
                raise AssertionError("Unexpected direct runtime access")
    with owner.begin() as conn:
        assert (
            conn.execute(
                text("""
            SELECT count(*) FROM membership_roles r JOIN organization_memberships m
            ON r.organization_id=m.organization_id AND r.membership_id=m.id
            WHERE m.user_id IN (:applicant,:invitee)
        """),
                {"applicant": APPLICANT, "invitee": INVITEE},
            ).scalar_one()
            == 0
        )
    print(
        "Organization joining: upgrade preservation, runtime isolation, invitation race and moderation passed."
    )


if __name__ == "__main__":
    owner_engine = create_database_engine()
    api_engine = role("veriq_api")
    if sys.argv[1:] == ["seed"]:
        seed(owner_engine, api_engine)
    else:
        run(owner_engine, api_engine)
