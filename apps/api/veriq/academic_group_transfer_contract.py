"""Standalone wire models for the proposed group transfer endpoint."""

from enum import Enum
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict
from starlette.responses import JSONResponse

from veriq.auth_audit import RequestContext


class TransferFailure(Enum):
    SESSION_INVALID = (401, "SESSION_INVALID")
    RESOURCE_NOT_FOUND = (404, "RESOURCE_NOT_FOUND")
    CSRF_DENIED = (403, "CSRF_DENIED")
    VALIDATION_ERROR = (422, "VALIDATION_ERROR")
    TRANSFER_CONFLICT = (409, "TRANSFER_CONFLICT")
    INTERNAL_ERROR = (500, "INTERNAL_ERROR")


def transfer_error_response(
    failure: TransferFailure, context: RequestContext
) -> JSONResponse:
    """Render a server-selected category without accepting exception or resource data."""
    status, code = failure.value
    return JSONResponse(
        status_code=status,
        content={
            "error": {
                "code": code,
                "message": "Transfer request could not be completed.",
                "request_id": str(context.request_id),
                "details": {},
            }
        },
        headers={"Cache-Control": "no-store"},
    )


def parse_transfer_idempotency_key(value: str | None) -> UUID:
    """Return the command UUID or reject a missing/invalid header without echoing it."""
    if value is None:
        raise ValueError("Idempotency-Key must be a UUID")
    try:
        return UUID(value)
    except ValueError:
        raise ValueError("Idempotency-Key must be a UUID") from None


class GroupTransferRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_interval_id: UUID
    target_group_id: UUID


class GroupTransferResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    result: Literal["transferred"]
    target_interval_id: UUID
