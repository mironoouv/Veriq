"""Standalone wire models for the proposed group transfer endpoint."""

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict


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
