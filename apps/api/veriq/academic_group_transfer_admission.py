"""Preliminary session admission for the isolated transfer adapter."""

from collections.abc import Callable
from uuid import UUID

from fastapi import Request
from starlette.concurrency import run_in_threadpool

from veriq.academic_group_transfer_contract import GroupTransferRequest, TransferFailure
from veriq.academic_group_transfer_http import AdmissionCheck, TransferAdmission
from veriq.auth_audit import RequestContext
from veriq.sessions import Sessions, SessionToken
from veriq.tenant_access import AccessDenied


def create_transfer_admission(
    *, sessions: Sessions, origin_csrf_valid: Callable[[Request], bool]
) -> AdmissionCheck:
    """Require the browser guard and resolve identity through the existing session boundary."""

    async def check(
        request: Request,
        tenant: UUID,
        payload: GroupTransferRequest,
        context: RequestContext,
    ) -> TransferAdmission | TransferFailure:
        if not origin_csrf_valid(request):
            return TransferFailure.CSRF_DENIED
        token = SessionToken(request.cookies.get("__Host-veriq-session", ""))
        try:
            gate = token._gate(sessions.policy)
            identity = await run_in_threadpool(sessions.resolve, token)
        except AccessDenied:
            return TransferFailure.SESSION_INVALID
        if identity.organization_id is None or identity.organization_id != tenant:
            return TransferFailure.RESOURCE_NOT_FOUND
        return TransferAdmission(tenant, identity.user_id, gate)

    return check
