from uuid import UUID

import pytest
from pydantic import ValidationError

from veriq.academic_group_transfer_contract import (
    GroupTransferRequest,
    GroupTransferResult,
    parse_transfer_idempotency_key,
)

SOURCE, TARGET = UUID(int=101), UUID(int=102)


def test_command_key() -> None:
    assert parse_transfer_idempotency_key(str(SOURCE)) == SOURCE
    assert parse_transfer_idempotency_key(str(SOURCE).upper()) == SOURCE


@pytest.mark.parametrize(
    "value", [None, "", " ", "invalid", "123", str(SOURCE) + ", " + str(TARGET)]
)
def test_invalid_command_key(value: str | None) -> None:
    with pytest.raises(ValueError) as error:
        parse_transfer_idempotency_key(value)
    assert str(error.value) == "Idempotency-Key must be a UUID"


def test_valid_request() -> None:
    request = GroupTransferRequest.model_validate(
        {"source_interval_id": str(SOURCE), "target_group_id": str(TARGET)}
    )
    assert request.source_interval_id == SOURCE
    assert request.target_group_id == TARGET
    assert (
        GroupTransferRequest(source_interval_id=SOURCE, target_group_id=TARGET)
        == request
    )


@pytest.mark.parametrize("field", ["source_interval_id", "target_group_id"])
def test_missing_request_field(field: str) -> None:
    payload = {"source_interval_id": str(SOURCE), "target_group_id": str(TARGET)}
    del payload[field]
    with pytest.raises(ValidationError):
        GroupTransferRequest.model_validate(payload)


@pytest.mark.parametrize("field", ["source_interval_id", "target_group_id"])
@pytest.mark.parametrize("invalid", ["invalid", "", None, 123, True, []])
def test_invalid_request_uuid(field: str, invalid: object) -> None:
    payload: dict[str, object] = {
        "source_interval_id": str(SOURCE),
        "target_group_id": str(TARGET),
    }
    payload[field] = invalid
    with pytest.raises(ValidationError):
        GroupTransferRequest.model_validate(payload)


@pytest.mark.parametrize(
    "field", ["tenant", "actor", "grant_epoch", "occurred_at", "unexpected"]
)
def test_extra_request_field(field: str) -> None:
    with pytest.raises(ValidationError):
        GroupTransferRequest.model_validate(
            {
                "source_interval_id": str(SOURCE),
                "target_group_id": str(TARGET),
                field: "synthetic",
            }
        )


def test_result_serialization() -> None:
    result = GroupTransferResult(result="transferred", target_interval_id=TARGET)
    assert result.model_dump(mode="json") == {
        "result": "transferred",
        "target_interval_id": str(TARGET),
    }
    assert GroupTransferResult.model_validate_json(result.model_dump_json()) == result


@pytest.mark.parametrize(
    "payload",
    [
        {"target_interval_id": str(TARGET)},
        {"result": "transferred"},
        {"result": "failed", "target_interval_id": str(TARGET)},
        {"result": "transferred", "target_interval_id": "invalid"},
        {"result": "transferred", "target_interval_id": None},
        {
            "result": "transferred",
            "target_interval_id": str(TARGET),
            "audit_id": str(SOURCE),
        },
    ],
)
def test_invalid_result(payload: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        GroupTransferResult.model_validate(payload)


def test_json_schema() -> None:
    request = GroupTransferRequest.model_json_schema()
    result = GroupTransferResult.model_json_schema()
    for schema, fields in (
        (request, {"source_interval_id", "target_group_id"}),
        (result, {"result", "target_interval_id"}),
    ):
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is False
        assert set(schema["properties"]) == fields
        assert set(schema["required"]) == fields
    for field in ("source_interval_id", "target_group_id"):
        assert request["properties"][field]["type"] == "string"
        assert request["properties"][field]["format"] == "uuid"
    assert result["properties"]["result"]["const"] == "transferred"
    assert result["properties"]["target_interval_id"]["format"] == "uuid"
