"""Test-only browser integration for the existing session lifecycle."""

import asyncio
import hmac
import os
import secrets
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field
from redis.asyncio import Redis
from sqlalchemy import Engine, text
from sqlalchemy.exc import SQLAlchemyError
from starlette.responses import JSONResponse, Response

from veriq.auth_audit import AuthEvent, AuthResult, RequestContext, append_attempt
from veriq.auth_credentials import CredentialVerifier
from veriq.auth_rate_limit import (
    AuthCategory,
    AuthLimitRejected,
    AuthRateLimiter,
    LimitBudget,
    trusted_client_ip,
)
from veriq.registration import Signup, _body_schema, _error, _payload
from veriq.registration_policy import HASHER, canonical_email
from veriq.sessions import Sessions, SessionToken
from veriq.tenant_access import AccessDenied

SESSION = "__Host-veriq-session"
CSRF = "__Host-veriq-csrf"
HEADERS = {"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"}


class Login(Signup):
    organization_id: UUID | None = Field(default=None, strict=False)


class Rotation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    organization_id: UUID | None = Field(strict=False)


@dataclass(frozen=True)
class Candidate:
    user_id: UUID
    version: int
    password_hash: str = field(repr=False)


class PasswordLogin:
    def __init__(self, verifier: CredentialVerifier) -> None:
        self.verifier = verifier
        self.dummy = HASHER.hash(secrets.token_urlsafe(32))

    def check(self, email: str, password: str) -> Candidate | None:
        with self.verifier.engine.connect() as connection:
            row = connection.execute(
                text("SELECT * FROM public.veriq_password_candidate(:email)"),
                {"email": email},
            ).one_or_none()
        candidate = (
            None
            if row is None
            else Candidate(row.id, row.credential_version, row.password_hash)
        )
        normalized = unicodedata.normalize("NFC", password)
        stored = self.dummy
        if candidate is not None:
            try:
                if not HASHER.check_needs_rehash(candidate.password_hash):
                    stored = candidate.password_hash
            except (InvalidHashError, VerificationError):
                pass
        valid: bool
        try:
            valid = HASHER.verify(stored, normalized)
        except (InvalidHashError, VerificationError, UnicodeError):
            valid = False
        return candidate if valid and stored != self.dummy else None


def login_enabled() -> bool:
    return (
        os.environ.get("VERIQ_ENV") == "test"
        and os.environ.get("VERIQ_ENABLE_TEST_LOGIN") == "1"
    )


def _set_cookie(response: Response, name: str, value: str) -> None:
    response.set_cookie(
        name, value, secure=True, httponly=True, samesite="lax", path="/"
    )


def _clear(response: Response) -> None:
    for name in (SESSION, CSRF):
        response.delete_cookie(
            name, secure=True, httponly=True, samesite="lax", path="/"
        )


def _audit(engine: Engine, context: RequestContext, result: AuthResult) -> None:
    with engine.begin() as connection:
        append_attempt(connection, uuid4(), context, AuthEvent.LOGIN, result)


def browser_router(
    engine: Engine, redis: Redis, verifier: Engine, issuer: Engine
) -> APIRouter:
    origin = os.environ["VERIQ_TEST_LOGIN_ORIGIN"]
    parsed = urlsplit(origin)
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username
        or origin != f"https://{parsed.netloc}"
    ):
        raise ValueError("Browser login requires one exact HTTPS origin")
    csrf_key = bytes.fromhex(os.environ["VERIQ_TEST_CSRF_KEY"])
    limit_key = bytes.fromhex(os.environ["VERIQ_TEST_AUTH_HMAC_KEY"])
    if len(csrf_key) < 32 or csrf_key == limit_key:
        raise ValueError("Browser login requires a separate CSRF key")
    limiter = AuthRateLimiter(
        redis, limit_key, dict.fromkeys(AuthCategory, LimitBudget(40, 10, 300))
    )
    passwords = PasswordLogin(CredentialVerifier(verifier))
    sessions = Sessions(engine, issuer=issuer)
    active: set[asyncio.Task[Candidate | None]] = set()
    router = APIRouter(prefix="/api/v1", tags=["auth-test"])

    def same_origin(request: Request) -> bool:
        return request.url.scheme == "https" and request.url.netloc == parsed.netloc

    def csrf_value(request: Request, nonce: str) -> str:
        binding = request.cookies.get(SESSION, "")
        return hmac.digest(csrf_key, f"{nonce}:{binding}".encode(), "sha256").hex()

    def csrf_valid(request: Request) -> bool:
        nonce = request.cookies.get(CSRF, "")
        header = request.headers.get("X-CSRF-Token", "")
        return (
            same_origin(request)
            and request.headers.getlist("Origin") == [origin]
            and len(nonce) == 43
            and len(header) == 64
            and hmac.compare_digest(
                csrf_value(request, nonce).encode(), header.encode()
            )
        )

    @router.get("/auth/csrf")
    async def csrf(request: Request) -> Response:
        context = RequestContext.new()
        if (
            not same_origin(request)
            or request.headers.get("X-Veriq-CSRF-Bootstrap") != "1"
            or request.headers.get("Origin", origin) != origin
        ):
            return _error(context, "CSRF_DENIED", 403)
        nonce = request.cookies.get(CSRF, "")
        if len(nonce) != 43:
            nonce = secrets.token_urlsafe(32)
        response = JSONResponse(
            {"csrf_token": csrf_value(request, nonce)}, headers=HEADERS
        )
        _set_cookie(response, CSRF, nonce)
        return response

    @router.post("/auth/login", status_code=204, openapi_extra=_body_schema(Login))
    async def login(request: Request) -> Response:
        context = RequestContext.new()
        if not csrf_valid(request):
            return _error(context, "CSRF_DENIED", 403)
        if SESSION in request.cookies:
            return _error(context, "LOGOUT_REQUIRED", 409)
        try:
            data = Login.model_validate(await _payload(request))
            email = canonical_email(data.email)
            if request.client is None:
                raise ValueError("Missing peer")
            ip = trusted_client_ip(request.client.host, None, ())
        except (ValueError, RecursionError):
            return _error(context, "INVALID_REQUEST", 400)

        try:
            await limiter.check(AuthCategory.LOGIN, ip, email)
        except AuthLimitRejected as error:
            rejected = error.response(context)
            rejected.headers.update(HEADERS)
            return rejected

        if len(active) >= 2:
            return _error(context, "SERVICE_UNAVAILABLE", 503)

        def complete(task: asyncio.Task[Candidate | None]) -> None:
            active.discard(task)
            if not task.cancelled():
                task.exception()

        def issue(candidate: Candidate) -> SessionToken:
            proof = passwords.verifier.confirm_password(
                candidate.user_id,
                candidate.version,
                organization_id=data.organization_id,
            )
            return sessions.issue(proof, context=context)

        try:
            task = asyncio.create_task(
                asyncio.to_thread(
                    passwords.check, email, data.password.get_secret_value()
                )
            )
            active.add(task)
            task.add_done_callback(complete)
            candidate = await asyncio.shield(task)
            if candidate is None:
                raise AccessDenied
            token = await asyncio.to_thread(issue, candidate)
        except AccessDenied:
            try:
                await asyncio.to_thread(_audit, engine, context, AuthResult.DENIED)
            except SQLAlchemyError:
                return _error(context, "SERVICE_UNAVAILABLE", 503)
            return _error(context, "INVALID_CREDENTIALS", 401)
        except SQLAlchemyError:
            return _error(context, "SERVICE_UNAVAILABLE", 503)

        response = Response(
            status_code=204,
            headers={**HEADERS, "X-Request-ID": str(context.request_id)},
        )
        _set_cookie(response, SESSION, token.value)
        response.delete_cookie(
            CSRF, secure=True, httponly=True, samesite="lax", path="/"
        )
        return response

    @router.get("/me")
    async def me(request: Request) -> Response:
        context = RequestContext.new()
        if not same_origin(request) or request.headers.get("Sec-Fetch-Site") in {
            "cross-site",
            "same-site",
        }:
            return _error(context, "CSRF_DENIED", 403)
        try:
            identity = await asyncio.to_thread(
                sessions.resolve, SessionToken(request.cookies.get(SESSION, ""))
            )
        except AccessDenied:
            return _error(context, "SESSION_REQUIRED", 401)
        except SQLAlchemyError:
            return _error(context, "SERVICE_UNAVAILABLE", 503)
        return JSONResponse(
            {
                "user_id": str(identity.user_id),
                "organization_id": str(identity.organization_id)
                if identity.organization_id
                else None,
            },
            headers=HEADERS,
        )

    async def revoke(request: Request, *, all_for_account: bool) -> Response:
        context = RequestContext.new()
        if not csrf_valid(request):
            return _error(context, "CSRF_DENIED", 403)
        try:
            count = await asyncio.to_thread(
                sessions.revoke,
                SessionToken(request.cookies.get(SESSION, "")),
                all_for_account=all_for_account,
                context=context,
            )
        except AccessDenied:
            count = 0
        except SQLAlchemyError:
            return _error(context, "SERVICE_UNAVAILABLE", 503)
        if all_for_account and not count:
            return _error(context, "SESSION_REQUIRED", 401)
        response = Response(status_code=204, headers=HEADERS)
        _clear(response)
        return response

    @router.post("/auth/logout", status_code=204)
    async def logout(request: Request) -> Response:
        return await revoke(request, all_for_account=False)

    @router.post("/auth/sessions/revoke", status_code=204)
    async def revoke_all(request: Request) -> Response:
        return await revoke(request, all_for_account=True)

    @router.post(
        "/auth/sessions/rotate", status_code=204, openapi_extra=_body_schema(Rotation)
    )
    async def rotate(request: Request) -> Response:
        context = RequestContext.new()
        if not csrf_valid(request):
            return _error(context, "CSRF_DENIED", 403)
        try:
            data = Rotation.model_validate(await _payload(request))
        except (ValueError, RecursionError):
            return _error(context, "INVALID_REQUEST", 400)
        try:
            token = await asyncio.to_thread(
                sessions.rotate,
                SessionToken(request.cookies.get(SESSION, "")),
                organization_id=data.organization_id,
            )
        except AccessDenied:
            return _error(context, "SESSION_OR_SCOPE_DENIED", 401)
        except SQLAlchemyError:
            return _error(context, "SERVICE_UNAVAILABLE", 503)
        response = Response(status_code=204, headers=HEADERS)
        _set_cookie(response, SESSION, token.value)
        response.delete_cookie(
            CSRF, secure=True, httponly=True, samesite="lax", path="/"
        )
        return response

    return router
