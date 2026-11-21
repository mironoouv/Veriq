"""Synthetic HTTP contract harness. It performs no authorization or database writes."""

from dataclasses import replace
from uuid import UUID

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from veriq.academic_group_teacher_policy import Assignment, Caller, Group, Membership
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
from veriq.permissions import SessionGate
from veriq.sessions import SessionPolicy

ORG, SOURCE, TARGET, KEY, CREATED, DIAGNOSTIC = (UUID(int=i) for i in range(101, 107))
PATH = "/api/v1/organizations/{organization_id}/academic-roster/transfers"
CATALOG = "/api/v1/organizations/{organization_id}/academic/{kind}"
URL = PATH.format(organization_id=ORG)
BODY = {"source_interval_id": str(SOURCE), "target_group_id": str(TARGET)}
CONTEXT = RequestContext(DIAGNOSTIC, DIAGNOSTIC)
PROOF = b"synthetic-session-proof-32-bytes!!"
GATE = SessionGate(TARGET, PROOF, SessionPolicy().limits)
HEADERS = {"Idempotency-Key": str(KEY)}


@pytest.mark.parametrize("actor_role", ["org_admin", "teacher"])
@pytest.mark.parametrize(
    ("scenario", "status", "code"),
    [
        ("allowed", 201, None),
        ("expired", 401, "SESSION_INVALID"),
        ("stale_epoch", 404, "RESOURCE_NOT_FOUND"),
        ("foreign_group", 404, "RESOURCE_NOT_FOUND"),
        ("foreign_student", 404, "RESOURCE_NOT_FOUND"),
        ("source_permission", 404, "RESOURCE_NOT_FOUND"),
        ("target_permission", 404, "RESOURCE_NOT_FOUND"),
        ("closed_initial", 404, "RESOURCE_NOT_FOUND"),
        ("closed_after_access", 409, "TRANSFER_CONFLICT"),
        ("archived", 409, "TRANSFER_CONFLICT"),
        ("archived_denied", 404, "RESOURCE_NOT_FOUND"),
    ],
)
def test_policy_drives_http(
    actor_role: str, scenario: str, status: int, code: str | None
) -> None:
    actor_id, student_id, other = UUID(int=201), UUID(int=202), UUID(int=203)
    permissions = frozenset({TRANSFER})
    actor = Membership(ORG, actor_id, 3, True, frozenset({actor_role}))
    caller = Caller(ORG, actor_id, 3, True, actor, permissions)
    student = Membership(ORG, student_id, 1, True, frozenset({"student"}))
    source = GroupAccess(
        Group(ORG, SOURCE, True),
        permissions,
        TeacherAuthority(Assignment(ORG, SOURCE, actor_id, False), 3),
    )
    target = GroupAccess(
        Group(ORG, TARGET, True),
        permissions,
        TeacherAuthority(Assignment(ORG, TARGET, actor_id, False), 3),
    )
    interval = SourceInterval(ORG, SOURCE, student_id, True)
    if scenario == "expired":
        caller = replace(caller, session_current=False)
    if scenario == "stale_epoch":
        caller = replace(caller, grant_epoch=2)
    if scenario == "foreign_group":
        target = replace(target, group=replace(target.group, organization_id=other))
    if scenario == "foreign_student":
        student = replace(student, organization_id=other)
    if scenario == "source_permission":
        source = replace(source, permissions=frozenset())
    if scenario == "target_permission":
        target = replace(target, permissions=frozenset())
    if scenario.startswith("closed"):
        interval = replace(interval, open=False)
    if scenario.startswith("archived"):
        target = replace(target, group=replace(target.group, active=False))
    if scenario == "archived_denied":
        target = replace(target, permissions=frozenset())
    calls: list[UUID] = []

    async def check(
        request: Request,
        tenant: UUID,
        payload: GroupTransferRequest,
        context: RequestContext,
    ) -> TransferAdmission:
        return TransferAdmission(ORG, actor_id, GATE)

    async def command(
        admission: TransferAdmission,
        payload: GroupTransferRequest,
        command_id: UUID,
        context: RequestContext,
    ) -> GroupTransferResult | TransferFailure:
        assert admission.actor_id == actor_id and admission.session_gate is GATE
        assert command_id == KEY and payload == GroupTransferRequest.model_validate(
            BODY
        )
        calls.append(command_id)
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
            else GroupTransferResult(result="transferred", target_interval_id=CREATED)
        )

    app = FastAPI()
    app.include_router(
        create_transfer_router(check_admission=check, execute=command), prefix="/api/v1"
    )
    with TestClient(app) as client:
        response = client.post(URL, json=BODY, headers=HEADERS)
    assert calls == [KEY]
    assert response.status_code == status
    assert response.headers["cache-control"] == "no-store"
    if code is None:
        assert response.json() == {
            "result": "transferred",
            "target_interval_id": str(CREATED),
        }
    else:
        assert_error(status, response.json(), TransferFailure[code])
    for hidden in (actor_id, student_id, other, KEY):
        assert str(hidden) not in response.text
    assert PROOF.decode() not in response.text and PROOF.hex() not in response.text


def test_openapi_contract() -> None:
    with TestClient(application(False)) as client:
        schema = client.get("/openapi.json").json()
    operation = schema["paths"][PATH]["post"]
    assert set(operation["responses"]) == {
        "201",
        "401",
        "403",
        "404",
        "409",
        "422",
        "500",
    }
    parameters = operation["parameters"]
    assert len(parameters) == 2
    header = next(p for p in parameters if p["in"] == "header")
    assert header["name"] == "Idempotency-Key" and header["required"] is True
    assert header["schema"] == {"type": "string", "format": "uuid"}
    path = next(p for p in parameters if p["in"] == "path")
    assert path["required"] is True and path["schema"]["format"] == "uuid"
    request = operation["requestBody"]
    assert request["required"] is True
    assert (
        request["content"]["application/json"]["schema"]
        == GroupTransferRequest.model_json_schema()
    )
    success = operation["responses"]["201"]["content"]["application/json"]["schema"]
    assert schema["components"]["schemas"][success["$ref"].split("/")[-1]] == (
        GroupTransferResult.model_json_schema()
    )
    for failure in TransferFailure:
        status, code = failure.value
        response = operation["responses"][str(status)]
        envelope = response["content"]["application/json"]["schema"]
        assert (
            envelope["required"] == ["error"]
            and envelope["additionalProperties"] is False
        )
        error = envelope["properties"]["error"]
        assert set(error["required"]) == {"code", "message", "request_id", "details"}
        assert set(error["properties"]) == set(error["required"])
        assert error["additionalProperties"] is False
        assert error["properties"]["code"]["const"] == code
        assert error["properties"]["request_id"]["format"] == "uuid"
        assert error["properties"]["details"]["additionalProperties"] is False
    for response in operation["responses"].values():
        assert response["headers"]["Cache-Control"]["schema"]["const"] == "no-store"
    assert "Origin/CSRF" in operation["description"]


def application(catalog_first: bool, failure: TransferFailure | None = None) -> FastAPI:
    app = FastAPI()

    async def check(
        request: Request,
        tenant: UUID,
        payload: GroupTransferRequest,
        context: RequestContext,
    ) -> TransferAdmission | TransferFailure:
        assert tenant == ORG
        return TransferAdmission(ORG, SOURCE, GATE)

    async def execute(
        admission: TransferAdmission,
        payload: GroupTransferRequest,
        command_id: UUID,
        context: RequestContext,
    ) -> GroupTransferResult | TransferFailure:
        assert command_id == KEY and payload == GroupTransferRequest.model_validate(
            BODY
        )
        if failure is not None:
            return failure
        return GroupTransferResult(result="transferred", target_interval_id=CREATED)

    async def catalog(organization_id: UUID, kind: str) -> dict[str, str]:
        return {"handler": "catalog", "kind": kind}

    if catalog_first:
        app.add_api_route(CATALOG, catalog, methods=["POST"])
    app.include_router(
        create_transfer_router(check_admission=check, execute=execute), prefix="/api/v1"
    )
    if not catalog_first:
        app.add_api_route(CATALOG, catalog, methods=["POST"])
    return app


@pytest.mark.parametrize("catalog_first", [False, True])
def test_success_and_route_independence(catalog_first: bool) -> None:
    with TestClient(application(catalog_first)) as client:
        response = client.post(URL, json=BODY, headers=HEADERS)
        assert response.status_code == 201
        assert PROOF.decode() not in response.text
        assert PROOF.hex() not in response.text
        assert response.headers["cache-control"] == "no-store"
        assert response.json() == {
            "result": "transferred",
            "target_interval_id": str(CREATED),
        }
        catalog = client.post(
            CATALOG.format(organization_id=ORG, kind="study_groups"), json={}
        )
        assert catalog.status_code == 200
        assert catalog.json() == {"handler": "catalog", "kind": "study_groups"}


def assert_error(
    response_status: int, body: dict[str, object], expected: TransferFailure
) -> None:
    assert response_status == expected.value[0]
    error = body["error"]
    assert isinstance(error, dict)
    diagnostic = UUID(error["request_id"])
    assert diagnostic != KEY
    assert body == {
        "error": {
            "code": expected.value[1],
            "message": "Transfer request could not be completed.",
            "request_id": str(diagnostic),
            "details": {},
        }
    }


@pytest.mark.parametrize("failure", list(TransferFailure))
def test_synthetic_failures(failure: TransferFailure) -> None:
    with TestClient(application(False, failure)) as client:
        response = client.post(URL, json=BODY, headers=HEADERS)
        assert_error(response.status_code, response.json(), failure)
        assert response.headers["cache-control"] == "no-store"
        for hidden in (SOURCE, TARGET, KEY, ORG):
            assert str(hidden) not in response.text
        assert PROOF.decode() not in response.text
        assert PROOF.hex() not in response.text


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"source_interval_id": str(SOURCE)},
        {
            "source_interval_id": "synthetic-private-input",
            "target_group_id": str(TARGET),
        },
        BODY | {"secret": "synthetic-private-input"},
        [],
    ],
)
def test_invalid_body(payload: object) -> None:
    with TestClient(application(False)) as client:
        response = client.post(URL, json=payload, headers=HEADERS)
        assert_error(
            response.status_code, response.json(), TransferFailure.VALIDATION_ERROR
        )
        assert response.headers["cache-control"] == "no-store"
        assert "synthetic-private-input" not in response.text


@pytest.mark.parametrize("key", [None, "", "synthetic-private-input"])
def test_invalid_header(key: str | None) -> None:
    headers = {} if key is None else {"Idempotency-Key": key}
    with TestClient(application(False)) as client:
        response = client.post(URL, json=BODY, headers=headers)
        assert_error(
            response.status_code, response.json(), TransferFailure.VALIDATION_ERROR
        )
        assert response.headers["cache-control"] == "no-store"
        assert "synthetic-private-input" not in response.text


@pytest.mark.parametrize("denial", list(TransferFailure))
def test_admission_denial_never_executes(denial: TransferFailure) -> None:
    async def check(
        request: Request,
        tenant: UUID,
        payload: GroupTransferRequest,
        context: RequestContext,
    ) -> TransferAdmission | TransferFailure:
        return denial

    async def execute(
        admission: TransferAdmission,
        payload: GroupTransferRequest,
        command_id: UUID,
        context: RequestContext,
    ) -> GroupTransferResult | TransferFailure:
        pytest.fail("Command invoked after denial")

    app = FastAPI()
    app.include_router(
        create_transfer_router(check_admission=check, execute=execute), prefix="/api/v1"
    )
    with TestClient(app) as client:
        response = client.post(URL, json=BODY, headers=HEADERS)
        assert_error(response.status_code, response.json(), denial)


def test_dependencies_and_context() -> None:
    calls: list[RequestContext] = []

    async def check(
        request: Request,
        tenant: UUID,
        payload: GroupTransferRequest,
        context: RequestContext,
    ) -> TransferAdmission | TransferFailure:
        calls.append(context)
        assert request.method == "POST" and tenant == ORG
        assert payload == GroupTransferRequest.model_validate(BODY)
        return TransferAdmission(ORG, SOURCE, GATE)

    async def execute(
        admission: TransferAdmission,
        payload: GroupTransferRequest,
        command_id: UUID,
        context: RequestContext,
    ) -> GroupTransferResult | TransferFailure:
        assert calls == [context]
        assert admission == TransferAdmission(ORG, SOURCE, GATE)
        assert admission.session_gate is GATE
        assert admission.session_gate.digest == PROOF
        assert (
            payload == GroupTransferRequest.model_validate(BODY) and command_id == KEY
        )
        calls.append(context)
        return GroupTransferResult(result="transferred", target_interval_id=CREATED)

    app = FastAPI()
    app.include_router(
        create_transfer_router(check_admission=check, execute=execute), prefix="/api/v1"
    )
    with TestClient(app) as client:
        for payload, headers in (({}, HEADERS), (BODY, {})):
            assert client.post(URL, json=payload, headers=headers).status_code == 422
            assert calls == []
        assert client.post(URL, json=BODY, headers=HEADERS).status_code == 201
        assert len(calls) == 2


def test_admission_representation_hides_proof() -> None:
    admission = TransferAdmission(ORG, SOURCE, GATE)
    for representation in (repr(admission), str(admission), repr(GATE)):
        assert PROOF.decode() not in representation
        assert PROOF.hex() not in representation


@pytest.mark.parametrize("stage", ["admission", "command", "tenant"])
def test_dependency_failure_is_redacted(stage: str) -> None:
    commands: list[UUID] = []

    async def check(
        request: Request,
        tenant: UUID,
        payload: GroupTransferRequest,
        context: RequestContext,
    ) -> TransferAdmission | TransferFailure:
        if stage == "admission":
            raise RuntimeError("synthetic-secret")
        return TransferAdmission(TARGET if stage == "tenant" else ORG, SOURCE, GATE)

    async def execute(
        admission: TransferAdmission,
        payload: GroupTransferRequest,
        command_id: UUID,
        context: RequestContext,
    ) -> GroupTransferResult | TransferFailure:
        commands.append(command_id)
        raise RuntimeError("synthetic-secret")

    app = FastAPI()
    app.include_router(
        create_transfer_router(check_admission=check, execute=execute), prefix="/api/v1"
    )
    with TestClient(app) as client:
        response = client.post(URL, json=BODY, headers=HEADERS)
        expected = (
            TransferFailure.RESOURCE_NOT_FOUND
            if stage == "tenant"
            else TransferFailure.INTERNAL_ERROR
        )
        assert_error(response.status_code, response.json(), expected)
        assert "synthetic-secret" not in response.text
        assert commands == ([KEY] if stage == "command" else [])
