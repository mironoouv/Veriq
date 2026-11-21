"""Isolated transfer adapter. Working application registration requires approval."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from json import JSONDecodeError
from uuid import UUID

from fastapi import APIRouter, Request
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


@dataclass(frozen=True)
class TransferAdmission:
    """Server-provided identity. The command must recheck authority transactionally."""

    organization_id: UUID
    actor_id: UUID
    session_id: UUID


AdmissionCheck = Callable[
    [Request, UUID, GroupTransferRequest, RequestContext],
    Awaitable[TransferAdmission | TransferFailure],
]
TransferCommand = Callable[
    [TransferAdmission, GroupTransferRequest, UUID, RequestContext],
    Awaitable[GroupTransferResult | TransferFailure],
]


def create_transfer_router(
    *, check_admission: AdmissionCheck, execute: TransferCommand
) -> APIRouter:
    router = APIRouter()

    @router.post("/organizations/{organization_id}/academic-roster/transfers")
    async def transfer(request: Request, organization_id: str) -> JSONResponse:
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
