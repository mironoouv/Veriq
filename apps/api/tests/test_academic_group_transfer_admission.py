from dataclasses import replace
from uuid import UUID

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from veriq.academic_group_teacher_policy import Assignment, Caller, Group, Membership
from veriq.academic_group_transfer_admission import create_transfer_admission
from veriq.academic_group_transfer_contract import (
    GroupTransferRequest,
    GroupTransferResult,
    TransferFailure,
)
from veriq.academic_group_transfer_http import TransferAdmission, create_transfer_router
from veriq.academic_group_transfer_policy import (
    TRANSFER,
    GroupAccess,
    SourceInterval,
    TeacherAuthority,
    classify_transfer,
)
from veriq.auth_audit import RequestContext
from veriq.sessions import (
    MfaLevel,
    SessionIdentity,
    SessionPolicy,
    Sessions,
    SessionToken,
)
from veriq.tenant_access import AccessDenied

ORG, OTHER, ACTOR, SOURCE, TARGET, KEY = (UUID(int=i) for i in range(1, 7))
TOKEN = SessionToken(f"{ACTOR.hex}." + "s" * 43)
BODY = {"source_interval_id": str(SOURCE), "target_group_id": str(TARGET)}
URL = f"/api/v1/organizations/{ORG}/academic-roster/transfers"


class SyntheticSessions(Sessions):
    def __init__(self, tenant: UUID | None, denied: bool) -> None:
        self.policy = SessionPolicy()
        self.resolved_tenant = tenant
        self.denied = denied
        self.calls = 0

    def resolve(self, token: SessionToken) -> SessionIdentity:
        self.calls += 1
        assert token == TOKEN
        if self.denied:
            raise AccessDenied
        return SessionIdentity(ACTOR, self.resolved_tenant, MfaLevel.VERIFIED)


@pytest.mark.parametrize(
    ("guard", "tenant", "denied", "cookie", "status", "code"),
    [
        (True, ORG, False, TOKEN.value, 201, None),
        (False, ORG, False, TOKEN.value, 403, "CSRF_DENIED"),
        (True, ORG, True, TOKEN.value, 401, "SESSION_INVALID"),
        (True, None, False, TOKEN.value, 404, "RESOURCE_NOT_FOUND"),
        (True, OTHER, False, TOKEN.value, 404, "RESOURCE_NOT_FOUND"),
        (True, ORG, False, "", 401, "SESSION_INVALID"),
        (True, ORG, False, "invalid-synthetic", 401, "SESSION_INVALID"),
    ],
)
def test_admission(
    guard: bool,
    tenant: UUID | None,
    denied: bool,
    cookie: str,
    status: int,
    code: str | None,
) -> None:
    sessions = SyntheticSessions(tenant, denied)
    commands: list[TransferAdmission] = []

    def browser_guard(request: Request) -> bool:
        assert request.headers["origin"] == "https://synthetic.invalid"
        return guard

    async def command(
        admission: TransferAdmission,
        payload: GroupTransferRequest,
        command_id: UUID,
        context: RequestContext,
    ) -> GroupTransferResult:
        assert admission.organization_id == ORG and admission.actor_id == ACTOR
        assert admission.session_gate == TOKEN._gate(sessions.policy)
        assert (
            payload == GroupTransferRequest.model_validate(BODY) and command_id == KEY
        )
        assert context.request_id != KEY
        commands.append(admission)
        return GroupTransferResult(result="transferred", target_interval_id=TARGET)

    app = FastAPI()
    app.include_router(
        create_transfer_router(
            check_admission=create_transfer_admission(
                sessions=sessions, origin_csrf_valid=browser_guard
            ),
            execute=command,
        ),
        prefix="/api/v1",
    )
    with TestClient(app, base_url="https://synthetic.invalid") as client:
        client.cookies.set("__Host-veriq-session", cookie)
        response = client.post(
            URL,
            json=BODY,
            headers={
                "Idempotency-Key": str(KEY),
                "Origin": "https://synthetic.invalid",
            },
        )
    assert response.status_code == status
    assert response.headers["cache-control"] == "no-store"
    assert len(commands) == (1 if status == 201 else 0)
    assert sessions.calls == (1 if guard and cookie == TOKEN.value else 0)
    if code is not None:
        assert response.json()["error"]["code"] == code
        assert response.json()["error"]["details"] == {}
    assert TOKEN.value not in response.text
    assert TOKEN._gate(sessions.policy).digest.hex() not in response.text


@pytest.mark.parametrize("actor_role", ["org_admin", "teacher"])
@pytest.mark.parametrize(
    ("scenario", "status", "code", "command_calls"),
    [
        ("success", 201, None, 1),
        ("csrf", 403, "CSRF_DENIED", 0),
        ("session", 401, "SESSION_INVALID", 0),
        ("tenant", 404, "RESOURCE_NOT_FOUND", 0),
        ("no_tenant", 404, "RESOURCE_NOT_FOUND", 0),
        ("source_permission", 404, "RESOURCE_NOT_FOUND", 1),
        ("target_permission", 404, "RESOURCE_NOT_FOUND", 1),
        ("foreign_student", 404, "RESOURCE_NOT_FOUND", 1),
        ("archived", 409, "TRANSFER_CONFLICT", 1),
        ("closed_initial", 404, "RESOURCE_NOT_FOUND", 1),
        ("closed_after_access", 409, "TRANSFER_CONFLICT", 1),
        ("revoked_after_admission", 401, "SESSION_INVALID", 1),
    ],
)
def test_admission_adapter_and_policy(
    actor_role: str, scenario: str, status: int, code: str | None, command_calls: int
) -> None:
    tenant = None if scenario == "no_tenant" else OTHER if scenario == "tenant" else ORG
    sessions = SyntheticSessions(tenant, scenario == "session")
    executed: list[UUID] = []
    student_id, created = UUID(int=101), UUID(int=102)

    def guard(request: Request) -> bool:
        return scenario != "csrf"

    async def command(
        admission: TransferAdmission,
        payload: GroupTransferRequest,
        command_id: UUID,
        context: RequestContext,
    ) -> GroupTransferResult | TransferFailure:
        assert admission.actor_id == ACTOR and admission.organization_id == ORG
        assert admission.session_gate == TOKEN._gate(sessions.policy)
        assert (
            payload == GroupTransferRequest.model_validate(BODY) and command_id == KEY
        )
        assert context.request_id != command_id
        executed.append(command_id)
        permissions = frozenset({TRANSFER})
        actor = Membership(
            admission.organization_id,
            admission.actor_id,
            3,
            True,
            frozenset({actor_role}),
        )
        caller = Caller(
            admission.organization_id,
            actor.id,
            actor.grant_epoch,
            scenario != "revoked_after_admission",
            actor,
            permissions,
        )
        source = GroupAccess(
            Group(ORG, SOURCE, True),
            permissions,
            TeacherAuthority(Assignment(ORG, SOURCE, actor.id, False), 3),
        )
        target = GroupAccess(
            Group(ORG, payload.target_group_id, scenario != "archived"),
            permissions,
            TeacherAuthority(Assignment(ORG, TARGET, actor.id, False), 3),
        )
        if scenario == "source_permission":
            source = replace(source, permissions=frozenset())
        if scenario == "target_permission":
            target = replace(target, permissions=frozenset())
        student = Membership(
            OTHER if scenario == "foreign_student" else ORG,
            student_id,
            1,
            True,
            frozenset({"student"}),
        )
        interval = SourceInterval(
            ORG, SOURCE, student_id, not scenario.startswith("closed")
        )
        failure = classify_transfer(
            caller,
            source,
            target,
            student,
            interval,
            access_previously_confirmed=scenario == "closed_after_access",
        )
        return (
            failure
            if failure is not None
            else GroupTransferResult(result="transferred", target_interval_id=created)
        )

    app = FastAPI()
    app.include_router(
        create_transfer_router(
            check_admission=create_transfer_admission(
                sessions=sessions, origin_csrf_valid=guard
            ),
            execute=command,
        ),
        prefix="/api/v1",
    )
    with TestClient(app, base_url="https://synthetic.invalid") as client:
        client.cookies.set("__Host-veriq-session", TOKEN.value)
        response = client.post(URL, json=BODY, headers={"Idempotency-Key": str(KEY)})
    assert response.status_code == status
    assert response.headers["cache-control"] == "no-store"
    assert len(executed) == command_calls
    assert sessions.calls == (0 if scenario == "csrf" else 1)
    if code is None:
        assert response.json() == {
            "result": "transferred",
            "target_interval_id": str(created),
        }
    else:
        error = response.json()["error"]
        assert set(error) == {"code", "message", "request_id", "details"}
        assert error["code"] == code and error["details"] == {}
        assert UUID(error["request_id"]) != KEY
        assert error["message"] == "Transfer request could not be completed."
    for hidden in (ACTOR, student_id, OTHER, KEY):
        assert str(hidden) not in response.text
    assert TOKEN.value not in response.text
    assert TOKEN._gate(sessions.policy).digest.hex() not in response.text
