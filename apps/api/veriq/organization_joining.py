"""Organization joining commands for the test-only HTTPS adapter."""

import re
import secrets
from enum import StrEnum
from hashlib import sha256
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator
from sqlalchemy import Engine, text

from veriq.auth_audit import RequestContext
from veriq.sessions import SessionPolicy, SessionToken
from veriq.tenant_access import AccessDenied


class JoinAction(StrEnum):
    ISSUE_INVITE = "issue_invite"
    ISSUE_CODE = "issue_code"
    REVOKE_INVITE = "revoke_invite"
    REVOKE_CODE = "revoke_code"
    REDEEM_INVITE = "redeem_invite"
    REDEEM_CODE = "redeem_code"
    APPLY = "apply"
    APPROVE = "approve"
    REJECT = "reject"
    SET_INTAKE = "set_intake"
    STATUS = "status"


class JoinCommand(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: JoinAction
    object_id: UUID | None = None
    recipient_id: UUID | None = None
    secret: SecretStr | None = None
    enabled: bool | None = Field(default=None, strict=True)
    quota: int | None = Field(default=None, strict=True, ge=1, le=1000)

    @model_validator(mode="after")
    def validate_fields(self) -> "JoinCommand":
        required = {
            JoinAction.ISSUE_INVITE: {"recipient_id", "enabled"},
            JoinAction.ISSUE_CODE: {"quota"},
            JoinAction.REVOKE_INVITE: {"object_id"},
            JoinAction.REVOKE_CODE: {"object_id"},
            JoinAction.REDEEM_INVITE: {"object_id", "secret"},
            JoinAction.REDEEM_CODE: {"object_id", "secret"},
            JoinAction.APPROVE: {"object_id"},
            JoinAction.REJECT: {"object_id"},
            JoinAction.SET_INTAKE: {"enabled"},
        }
        if self.model_fields_set - {"action"} != required.get(self.action, set()):
            raise ValueError("Unexpected or missing command fields")
        if any(getattr(self, field) is None for field in self.model_fields_set):
            raise ValueError("Command fields cannot be null")
        if (
            self.secret is not None
            and re.fullmatch(r"[A-Za-z0-9_-]{43}", self.secret.get_secret_value())
            is None
        ):
            raise ValueError("Invalid secret")
        return self


class OrganizationJoining:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self.policy = SessionPolicy.from_environment()

    def execute(
        self,
        org: UUID,
        token: SessionToken,
        command: JoinCommand,
        context: RequestContext,
    ) -> dict[str, str]:
        gate = token._gate(self.policy)
        object_id = command.object_id
        secret = (
            command.secret.get_secret_value() if command.secret is not None else None
        )
        issuing = command.action in {JoinAction.ISSUE_INVITE, JoinAction.ISSUE_CODE}
        if issuing:
            object_id = uuid4()
            secret = secrets.token_urlsafe(32)
        with self.engine.begin() as connection:
            result: str | None = connection.execute(
                text("""SELECT public.veriq_organization_join(
                    :session,:digest,CAST(:limits AS interval[]),:org,:action,:object,
                    :recipient,:secret,:flag,:quota,:event,:correlation
                )"""),
                {
                    "session": gate.session_id,
                    "digest": gate.digest,
                    "limits": list(self.policy.limits),
                    "org": org,
                    "action": command.action.value,
                    "object": object_id,
                    "recipient": command.recipient_id,
                    "secret": sha256(secret.encode("ascii")).digest()
                    if secret
                    else None,
                    "flag": command.enabled,
                    "quota": command.quota,
                    "event": uuid4(),
                    "correlation": context.correlation_id,
                },
            ).scalar_one()
        if result is None:
            raise AccessDenied
        status, _, request_id = result.partition(":")
        response = {"status": status}
        if request_id:
            response["request_id"] = request_id
        if issuing and secret is not None:
            response.update(object_id=str(object_id), secret=secret)
        return response
