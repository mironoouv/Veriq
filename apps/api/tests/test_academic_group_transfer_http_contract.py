"""Synthetic HTTP contract harness. It performs no authorization or database writes."""

from collections.abc import Callable
from uuid import UUID

import pytest
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.testclient import TestClient
from starlette.responses import JSONResponse

from veriq.academic_group_transfer_contract import (
    GroupTransferRequest,
    GroupTransferResult,
    TransferFailure,
    parse_transfer_idempotency_key,
    transfer_error_response,
)
from veriq.auth_audit import RequestContext

ORG, SOURCE, TARGET, KEY, CREATED, DIAGNOSTIC = (UUID(int=i) for i in range(101, 107))
PATH = "/api/v1/organizations/{organization_id}/academic-roster/transfers"
CATALOG = "/api/v1/organizations/{organization_id}/academic/{kind}"
URL = PATH.format(organization_id=ORG)
BODY = {"source_interval_id": str(SOURCE), "target_group_id": str(TARGET)}
CONTEXT = RequestContext(DIAGNOSTIC, DIAGNOSTIC)
HEADERS = {"Idempotency-Key": str(KEY)}


def application(catalog_first: bool, failure: TransferFailure | None = None) -> FastAPI:
    app = FastAPI()

    @app.exception_handler(RequestValidationError)
    async def invalid(request: Request, error: RequestValidationError) -> JSONResponse:
        return transfer_error_response(TransferFailure.VALIDATION_ERROR, CONTEXT)

    async def transfer(
        organization_id: UUID, payload: GroupTransferRequest, request: Request
    ) -> JSONResponse:
        try:
            command_id = parse_transfer_idempotency_key(
                request.headers.get("Idempotency-Key")
            )
        except ValueError:
            return transfer_error_response(TransferFailure.VALIDATION_ERROR, CONTEXT)
        assert organization_id == ORG and command_id == KEY
        assert payload == GroupTransferRequest.model_validate(BODY)
        if failure is not None:
            return transfer_error_response(failure, CONTEXT)
        result = GroupTransferResult(result="transferred", target_interval_id=CREATED)
        return JSONResponse(
            result.model_dump(mode="json"),
            status_code=201,
            headers={"Cache-Control": "no-store"},
        )

    async def catalog(organization_id: UUID, kind: str) -> dict[str, str]:
        return {"handler": "catalog", "kind": kind}

    handlers: list[tuple[str, Callable[..., object]]] = [
        (PATH, transfer),
        (CATALOG, catalog),
    ]
    if catalog_first:
        handlers.reverse()
    for path, handler in handlers:
        app.add_api_route(path, handler, methods=["POST"])
    return app


@pytest.mark.parametrize("catalog_first", [False, True])
def test_success_and_route_independence(catalog_first: bool) -> None:
    with TestClient(application(catalog_first)) as client:
        response = client.post(URL, json=BODY, headers=HEADERS)
        assert response.status_code == 201
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


def assert_error(response_status: int, body: object, expected: TransferFailure) -> None:
    assert response_status == expected.value[0]
    assert body == {
        "error": {
            "code": expected.value[1],
            "message": "Transfer request could not be completed.",
            "request_id": str(DIAGNOSTIC),
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
