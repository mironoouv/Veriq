"""Isolated transfer adapter. Working application registration requires approval."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from json import JSONDecodeError
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Path, Request
from pydantic import ValidationError
from starlette.responses import JSONResponse

from veriq.academic_group_transfer_contract import (
    GroupTransferRequest,
    GroupTransferResult,
    TransferFailure,
    parse_transfer_idempotency_key,
    transfer_error_response,
)
from veriq.auth_audit import RequestContext
from veriq.permissions import SessionGate


@dataclass(frozen=True)
class TransferAdmission:
    """Server-provided identity. The command must recheck authority transactionally."""

    organization_id: UUID
    actor_id: UUID
    session_gate: SessionGate = field(repr=False)


AdmissionCheck = Callable[
    [Request, UUID, GroupTransferRequest, RequestContext],
    Awaitable[TransferAdmission | TransferFailure],
]
TransferCommand = Callable[
    [TransferAdmission, GroupTransferRequest, UUID, RequestContext],
    Awaitable[GroupTransferResult | TransferFailure],
]

NO_STORE = {
    "Cache-Control": {
        "description": "Responses must not be stored.",
        "schema": {"type": "string", "const": "no-store"},
    }
}


def create_transfer_router(
    *, check_admission: AdmissionCheck, execute: TransferCommand
) -> APIRouter:
    router = APIRouter()

    @router.post(
        "/organizations/{organization_id}/academic-roster/transfers",
        status_code=201,
        response_model=GroupTransferResult,
        description=(
            "PROPOSED isolated adapter. Requires the existing browser session cookie "
            "and server Origin/CSRF validation. Tenant must match the verified session. "
            "Every response uses Cache-Control: no-store."
        ),
        responses={
            201: {"description": "Transfer committed.", "headers": NO_STORE},
            **{
                status: {
                    "description": code,
                    "headers": NO_STORE,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["error"],
                                "additionalProperties": False,
                                "properties": {
                                    "error": {
                                        "type": "object",
                                        "required": [
                                            "code",
                                            "message",
                                            "request_id",
                                            "details",
                                        ],
                                        "additionalProperties": False,
                                        "properties": {
                                            "code": {"type": "string", "const": code},
                                            "message": {
                                                "type": "string",
                                                "const": "Transfer request could not be completed.",
                                            },
                                            "request_id": {
                                                "type": "string",
                                                "format": "uuid",
                                            },
                                            "details": {
                                                "type": "object",
                                                "properties": {},
                                                "additionalProperties": False,
                                            },
                                        },
                                    }
                                },
                            }
                        }
                    },
                }
                for status, code in (failure.value for failure in TransferFailure)
            },
        },
        openapi_extra={
            "parameters": [
                {
                    "name": "Idempotency-Key",
                    "in": "header",
                    "required": True,
                    "schema": {"type": "string", "format": "uuid"},
                    "description": "Command UUID, distinct from the diagnostic request_id.",
                }
            ],
            "requestBody": {
                "required": True,
                "content": {
                    "application/json": {
                        "schema": GroupTransferRequest.model_json_schema()
                    }
                },
            },
        },
    )
    async def transfer(
        request: Request,
        organization_id: Annotated[str, Path(json_schema_extra={"format": "uuid"})],
    ) -> JSONResponse:
        context = RequestContext.new()
        try:
            tenant = UUID(organization_id)
            command_id = parse_transfer_idempotency_key(
                request.headers.get("Idempotency-Key")
            )
            payload = GroupTransferRequest.model_validate(await request.json())
        except (ValueError, ValidationError, JSONDecodeError, UnicodeDecodeError):
            return transfer_error_response(TransferFailure.VALIDATION_ERROR, context)

        try:
            admission = await check_admission(request, tenant, payload, context)
            if isinstance(admission, TransferFailure):
                return transfer_error_response(admission, context)
            if admission.organization_id != tenant:
                return transfer_error_response(
                    TransferFailure.RESOURCE_NOT_FOUND, context
                )
            result = await execute(admission, payload, command_id, context)
            if isinstance(result, TransferFailure):
                return transfer_error_response(result, context)
            return JSONResponse(
                result.model_dump(mode="json"),
                status_code=201,
                headers={"Cache-Control": "no-store"},
            )
        except Exception:  # noqa: BLE001 -- HTTP boundary must redact dependency failures.
            return transfer_error_response(TransferFailure.INTERNAL_ERROR, context)

    return router
