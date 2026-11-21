from uuid import UUID

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from veriq.academic_group_transfer_admission import create_transfer_admission
from veriq.academic_group_transfer_contract import (
    GroupTransferRequest,
    GroupTransferResult,
)
from veriq.academic_group_transfer_http import TransferAdmission, create_transfer_router
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
