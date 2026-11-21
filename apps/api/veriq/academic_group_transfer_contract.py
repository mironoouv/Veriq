"""Standalone wire models for the proposed group transfer endpoint."""

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class GroupTransferRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_interval_id: UUID
    target_group_id: UUID


class GroupTransferResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    result: Literal["transferred"]
    target_interval_id: UUID
