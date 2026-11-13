"""Test-only browser integration for the existing session lifecycle."""

import asyncio
import hmac
import os
import secrets
import unicodedata
from dataclasses import dataclass, field, replace
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.exceptions import InvalidTag
from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from redis.asyncio import Redis
from sqlalchemy import Engine, text
from sqlalchemy.exc import SQLAlchemyError
from starlette.responses import HTMLResponse, JSONResponse, Response

from veriq.academic_catalog import (
    AcademicCatalog,
    CatalogArchive,
    CatalogConflict,
    CatalogEdit,
    CatalogInput,
    CatalogKind,
    CatalogPage,
    CatalogRestore,
    CatalogRow,
)
from veriq.auth_audit import AuthEvent, AuthResult, RequestContext, append_attempt
from veriq.auth_credentials import CredentialProof, CredentialVerifier
from veriq.auth_rate_limit import (
    AuthCategory,
    AuthLimitRejected,
    AuthRateLimiter,
    LimitBudget,
    trusted_client_ip,
)
from veriq.bulk_import import BulkImport
from veriq.bulk_import_format import MAX_UPLOAD
from veriq.mfa import Mfa, Purpose
from veriq.mfa_recovery import MfaRecovery, RecoveryAction
from veriq.organization_joining import JoinCommand, OrganizationJoining
from veriq.password_recovery import PasswordRecovery
from veriq.password_work import PasswordCapacityExceeded, PasswordWork
from veriq.registration import Address, Signup, Verify, _body_schema, _error, _payload
from veriq.registration_policy import HASHER, canonical_email, supported_hash
from veriq.sessions import MfaRequired, Sessions, SessionToken
from veriq.tenant_access import AccessDenied

SESSION = "__Host-veriq-session"
CSRF = "__Host-veriq-csrf"
CHALLENGE = "__Host-veriq-mfa-challenge"
HEADERS = {"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"}


class Login(Signup):
    organization_id: UUID | None = Field(default=None, strict=False)


class MfaCode(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    code: SecretStr
    recovery: bool = False


class StepUp(BaseModel):
    model_config = ConfigDict(extra="forbid")
    purpose: Purpose
    resource_id: UUID | None = None


class RecoveryCommand(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: RecoveryAction
    operation_id: UUID
    source_id: UUID | None = None


class RecoveryEnrollment(Signup):
    capability: SecretStr


class RecoveryComplete(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    capability: SecretStr
    code: SecretStr


class ChangePassword(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    current_password: SecretStr
    new_password: SecretStr


class Rotation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    organization_id: UUID | None = Field(strict=False)


@dataclass(frozen=True)
class Candidate:
    user_id: UUID
    version: int
    password_hash: str = field(repr=False)
    replacement: str | None = field(default=None, repr=False)


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
        if candidate is not None and supported_hash(candidate.password_hash):
            try:
                HASHER.verify(candidate.password_hash, normalized)
            except VerifyMismatchError:
                return None
            except (InvalidHashError, VerificationError, UnicodeError):
                pass
            else:
                if HASHER.check_needs_rehash(candidate.password_hash):
                    return replace(candidate, replacement=HASHER.hash(normalized))
                return candidate

        try:
            HASHER.verify(self.dummy, normalized)
        except (VerificationError, UnicodeError):
            pass
        return None


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
    for name in (SESSION, CSRF, CHALLENGE):
        response.delete_cookie(
            name, secure=True, httponly=True, samesite="lax", path="/"
        )


def _audit(engine: Engine, context: RequestContext, result: AuthResult) -> None:
    with engine.begin() as connection:
        append_attempt(connection, uuid4(), context, AuthEvent.LOGIN, result)


def password_reset_page() -> HTMLResponse:
    nonce = secrets.token_urlsafe(24)
    return HTMLResponse(
        f"""<!doctype html><html lang="en"><meta charset="utf-8">
        <title>Reset password</title>
        <form><label>Email <input type="email" name="email" required></label>
        <label>New password <input type="password" name="password" autocomplete="new-password" required></label>
        <button type="submit">Reset password</button></form><output></output>
        <script nonce="{nonce}">
        let proof = location.hash.slice(1);
        history.replaceState(null, "", location.pathname);
        const form = document.querySelector("form");
        const output = document.querySelector("output");
        form.addEventListener("submit", async (event) => {{
          event.preventDefault();
          if (!form.reportValidity()) return;
          try {{
            const bootstrap = await fetch("/api/v1/auth/csrf", {{
              headers: {{"X-Veriq-CSRF-Bootstrap": "1"}}
            }});
            if (!bootstrap.ok) throw new Error("CSRF unavailable");
            const token = (await bootstrap.json()).csrf_token;
            const values = Object.fromEntries(new FormData(form));
            const result = await fetch(location.pathname, {{
              method: "POST", headers: {{"Content-Type": "application/json", "X-CSRF-Token": token}},
              body: JSON.stringify({{...values, proof}})
            }});
            output.textContent = result.ok ? "Password reset. Sign in again." : "Password reset failed.";
            if (result.ok) {{ proof = ""; form.reset(); }}
          }} catch {{ output.textContent = "Password reset unavailable."; }}
        }});
        </script></html>""",
        headers={
            **HEADERS,
            "Content-Security-Policy": (
                f"default-src 'none'; script-src 'nonce-{nonce}'; connect-src 'self'; "
                "form-action 'none'; base-uri 'none'; frame-ancestors 'none'"
            ),
            "X-Content-Type-Options": "nosniff",
        },
    )


def browser_router(
    engine: Engine,
    redis: Redis,
    verifier: Engine,
    issuer: Engine,
    mfa: Mfa | None = None,
    recovery: PasswordRecovery | None = None,
    mfa_recovery: MfaRecovery | None = None,
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
        redis,
        limit_key,
        {
            category: LimitBudget(30, 5, 180)
            if category
            in {
                AuthCategory.MFA,
                AuthCategory.MFA_RECOVERY,
                AuthCategory.PASSWORD_RESET,
                AuthCategory.PASSWORD_RESET_CONFIRM,
                AuthCategory.PASSWORD_CHANGE,
            }
            else LimitBudget(40, 10, 300)
            for category in AuthCategory
        },
    )
    passwords = PasswordLogin(CredentialVerifier(verifier))
    sessions = Sessions(engine, issuer=issuer)
    work = PasswordWork[Candidate | None](
        int(os.environ.get("VERIQ_TEST_LOGIN_HASH_CONCURRENCY", "2"))
    )
    router = APIRouter(prefix="/api/v1", tags=["auth-test"])

    def same_origin(request: Request) -> bool:
        return request.url.scheme == "https" and request.url.netloc == parsed.netloc

    def csrf_value(request: Request, nonce: str) -> str:
        binding = request.cookies.get(SESSION, "")
        challenge = request.cookies.get(CHALLENGE, "")
        return hmac.digest(
            csrf_key, f"{nonce}:{binding}:{challenge}".encode(), "sha256"
        ).hex()

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

        def issue(candidate: Candidate) -> tuple[SessionToken, bool]:
            proof = passwords.verifier.confirm_password(
                candidate.user_id,
                candidate.version,
                organization_id=data.organization_id,
                expected_hash=candidate.password_hash,
                replacement=candidate.replacement,
                context=context,
            )
            if mfa is not None:
                challenge = mfa.begin_login(proof)
                if challenge is not None:
                    return challenge, True
            return sessions.issue(proof, context=context, browser=True), False

        try:
            candidate = await work.run(
                lambda: passwords.check(email, data.password.get_secret_value())
            )
            if candidate is None:
                raise AccessDenied
            token, requires_mfa = await asyncio.to_thread(issue, candidate)
        except PasswordCapacityExceeded:
            return _error(context, "SERVICE_UNAVAILABLE", 503)
        except MfaRequired:
            return _error(context, "INVALID_CREDENTIALS", 401)
        except AccessDenied:
            try:
                await asyncio.to_thread(_audit, engine, context, AuthResult.DENIED)
            except SQLAlchemyError:
                return _error(context, "SERVICE_UNAVAILABLE", 503)
            return _error(context, "INVALID_CREDENTIALS", 401)
        except SQLAlchemyError:
            return _error(context, "SERVICE_UNAVAILABLE", 503)

        if requires_mfa:
            return challenge_response(token)
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
                context=context,
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

    def challenge_response(token: SessionToken) -> Response:
        response = JSONResponse(
            {"status": "mfa_required"}, status_code=202, headers=HEADERS
        )
        response.set_cookie(
            CHALLENGE,
            token.value,
            max_age=180,
            secure=True,
            httponly=True,
            samesite="lax",
            path="/",
        )
        response.delete_cookie(
            CSRF, secure=True, httponly=True, samesite="lax", path="/"
        )
        return response

    def enable_mfa(service: Mfa) -> None:
        async def check_mfa_rate(request: Request, subject: UUID | None) -> None:
            if request.client is None:
                raise AccessDenied
            ip = trusted_client_ip(request.client.host, None, ())
            await limiter.check(
                AuthCategory.MFA,
                ip,
                str(subject) if subject else f"invalid:{ip}",
            )

        def rate_response(
            error: AuthLimitRejected, context: RequestContext
        ) -> Response:
            response = error.response(context)
            response.headers.update(HEADERS)
            return response

        @router.post("/auth/mfa/challenge", openapi_extra=_body_schema(MfaCode))
        async def complete_mfa(request: Request) -> Response:
            context = RequestContext.new()
            if not csrf_valid(request):
                return _error(context, "CSRF_DENIED", 403)
            try:
                data = MfaCode.model_validate(await _payload(request))
            except (ValueError, RecursionError):
                return _error(context, "INVALID_REQUEST", 400)
            challenge = SessionToken(request.cookies.get(CHALLENGE, ""))
            current = request.cookies.get(SESSION)
            try:
                try:
                    subject = await asyncio.to_thread(
                        service.challenge_subject, challenge
                    )
                except AccessDenied:
                    subject = None
                await check_mfa_rate(request, subject)
                completion = await asyncio.to_thread(
                    service.finish,
                    challenge,
                    data.code.get_secret_value(),
                    recovery=data.recovery,
                    current=SessionToken(current) if current is not None else None,
                    context=context,
                )
            except AuthLimitRejected as error:
                return rate_response(error, context)
            except AccessDenied:
                return _error(context, "MFA_DENIED", 401)
            except (SQLAlchemyError, InvalidTag, KeyError):
                return _error(context, "SERVICE_UNAVAILABLE", 503)
            response = (
                JSONResponse(
                    {"recovery_codes": completion.recovery_codes}, headers=HEADERS
                )
                if completion.recovery_codes
                else Response(status_code=204, headers=HEADERS)
            )
            _clear(response)
            _set_cookie(response, SESSION, completion.token.value)
            return response

        @router.post("/auth/mfa/step-up", openapi_extra=_body_schema(StepUp))
        async def step_up(request: Request) -> Response:
            context = RequestContext.new()
            if not csrf_valid(request):
                return _error(context, "CSRF_DENIED", 403)
            try:
                data = StepUp.model_validate(await _payload(request))
            except (ValueError, RecursionError):
                return _error(context, "INVALID_REQUEST", 400)
            token = SessionToken(request.cookies.get(SESSION, ""))
            try:
                identity = await asyncio.to_thread(sessions.resolve, token)
                await check_mfa_rate(request, identity.user_id)
                return challenge_response(
                    await asyncio.to_thread(
                        service.begin_step_up, token, data.purpose, data.resource_id
                    )
                )
            except AuthLimitRejected as error:
                return rate_response(error, context)
            except AccessDenied:
                return _error(context, "MFA_DENIED", 401)
            except SQLAlchemyError:
                return _error(context, "SERVICE_UNAVAILABLE", 503)

        @router.post("/auth/mfa/disable", status_code=204)
        async def disable(request: Request) -> Response:
            context = RequestContext.new()
            if not csrf_valid(request):
                return _error(context, "CSRF_DENIED", 403)
            token = SessionToken(request.cookies.get(SESSION, ""))
            try:
                identity = await asyncio.to_thread(sessions.resolve, token)
                await check_mfa_rate(request, identity.user_id)
                await asyncio.to_thread(service.disable, token, context)
            except AuthLimitRejected as error:
                return rate_response(error, context)
            except AccessDenied:
                return _error(context, "MFA_DENIED", 401)
            except SQLAlchemyError:
                return _error(context, "SERVICE_UNAVAILABLE", 503)
            response = Response(status_code=204, headers=HEADERS)
            _clear(response)
            return response

    if mfa is not None:
        enable_mfa(mfa)

    def enable_recovery(service: PasswordRecovery) -> None:
        password_work = PasswordWork[None]()

        async def recovery_rate(
            request: Request, category: AuthCategory, identifier: str
        ) -> None:
            if request.client is None:
                raise AccessDenied
            await limiter.check(
                category, trusted_client_ip(request.client.host, None, ()), identifier
            )

        def rate_error(error: AuthLimitRejected, context: RequestContext) -> Response:
            response = error.response(context)
            response.headers.update(HEADERS)
            return response

        @router.post(
            "/auth/password/change",
            status_code=204,
            openapi_extra=_body_schema(ChangePassword),
        )
        async def change_password(request: Request) -> Response:
            context = RequestContext.new()
            if not csrf_valid(request):
                return _error(context, "CSRF_DENIED", 403)
            try:
                data = ChangePassword.model_validate(await _payload(request))
            except (ValueError, RecursionError):
                return _error(context, "INVALID_REQUEST", 400)
            token = SessionToken(request.cookies.get(SESSION, ""))
            try:
                identity = await asyncio.to_thread(sessions.resolve, token)
                await recovery_rate(
                    request, AuthCategory.PASSWORD_CHANGE, str(identity.user_id)
                )
                await password_work.run(
                    lambda: service.change(
                        token,
                        data.current_password.get_secret_value(),
                        data.new_password.get_secret_value(),
                        context,
                    )
                )
            except AuthLimitRejected as error:
                return rate_error(error, context)
            except AccessDenied:
                return _error(context, "PASSWORD_CHANGE_DENIED", 401)
            except ValueError:
                return _error(context, "PASSWORD_REJECTED", 400)
            except (SQLAlchemyError, PasswordCapacityExceeded):
                return _error(context, "SERVICE_UNAVAILABLE", 503)
            response = Response(status_code=204, headers=HEADERS)
            _clear(response)
            return response

        @router.post(
            "/auth/password-reset/request",
            status_code=202,
            openapi_extra=_body_schema(Address),
        )
        async def request_password_reset(request: Request) -> Response:
            context = RequestContext.new()
            if not csrf_valid(request):
                return _error(context, "CSRF_DENIED", 403)
            try:
                data = Address.model_validate(await _payload(request))
                email = canonical_email(data.email)
            except (ValueError, RecursionError):
                return _error(context, "INVALID_REQUEST", 400)
            try:
                await recovery_rate(request, AuthCategory.PASSWORD_RESET, email)
                await asyncio.to_thread(service.request, email, context)
            except AuthLimitRejected as error:
                return rate_error(error, context)
            except (AccessDenied, SQLAlchemyError):
                return _error(context, "SERVICE_UNAVAILABLE", 503)
            return Response(status_code=202, headers=HEADERS)

        @router.post(
            "/auth/password-reset/confirm",
            status_code=204,
            openapi_extra=_body_schema(Verify),
        )
        async def confirm_password_reset(request: Request) -> Response:
            context = RequestContext.new()
            if not csrf_valid(request):
                return _error(context, "CSRF_DENIED", 403)
            try:
                data = Verify.model_validate(await _payload(request))
                email = canonical_email(data.email)
            except (ValueError, RecursionError):
                return _error(context, "INVALID_REQUEST", 400)
            try:
                await recovery_rate(request, AuthCategory.PASSWORD_RESET_CONFIRM, email)
                await password_work.run(
                    lambda: service.confirm(
                        SessionToken(data.proof.get_secret_value()),
                        email,
                        data.password.get_secret_value(),
                        context,
                    )
                )
            except AuthLimitRejected as error:
                return rate_error(error, context)
            except AccessDenied:
                return _error(context, "INVALID_PROOF", 400)
            except ValueError:
                return _error(context, "PASSWORD_REJECTED", 400)
            except (SQLAlchemyError, PasswordCapacityExceeded):
                return _error(context, "SERVICE_UNAVAILABLE", 503)
            response = Response(status_code=204, headers=HEADERS)
            _clear(response)
            return response

        @router.get("/auth/password-reset/confirm", include_in_schema=False)
        async def reset_page(request: Request) -> Response:
            if not same_origin(request):
                return _error(RequestContext.new(), "CSRF_DENIED", 403)
            return password_reset_page()

    if recovery is not None:
        enable_recovery(recovery)

    def enable_recovery_workflow(service: MfaRecovery) -> None:
        async def guard(
            request: Request, context: RequestContext, subject: str
        ) -> Response | None:
            if not csrf_valid(request):
                return _error(context, "CSRF_DENIED", 403)
            if request.client is None:
                return _error(context, "INVALID_REQUEST", 400)
            try:
                await limiter.check(
                    AuthCategory.MFA_RECOVERY,
                    trusted_client_ip(request.client.host, None, ()),
                    subject,
                )
            except AuthLimitRejected as error:
                response = error.response(context)
                response.headers.update(HEADERS)
                return response
            return None

        async def primary(
            email: str, raw: str, context: RequestContext
        ) -> tuple[Candidate, CredentialProof]:
            candidate = await work.run(lambda: passwords.check(email, raw))
            if candidate is None:
                raise AccessDenied
            proof = await asyncio.to_thread(
                passwords.verifier.confirm_password,
                candidate.user_id,
                candidate.version,
                organization_id=None,
                expected_hash=candidate.password_hash,
                replacement=candidate.replacement,
                context=context,
            )
            return candidate, proof

        @router.post(
            "/auth/mfa/recovery", status_code=202, openapi_extra=_body_schema(Signup)
        )
        async def start_recovery(request: Request) -> Response:
            context = RequestContext.new()
            if not csrf_valid(request):
                return _error(context, "CSRF_DENIED", 403)
            try:
                data = Signup.model_validate(await _payload(request))
                email = canonical_email(data.email)
            except (ValueError, RecursionError):
                return _error(context, "INVALID_REQUEST", 400)
            rejection = await guard(request, context, "start:" + email)
            if rejection is not None:
                return rejection
            try:
                _, proof = await primary(
                    email, data.password.get_secret_value(), context
                )
                await asyncio.to_thread(service.start, proof, context)
            except AccessDenied:
                pass
            except (SQLAlchemyError, PasswordCapacityExceeded):
                return _error(context, "SERVICE_UNAVAILABLE", 503)
            return Response(status_code=202, headers=HEADERS)

        @router.post(
            "/auth/mfa/recovery/{case}/action",
            openapi_extra=_body_schema(RecoveryCommand),
        )
        async def recovery_action(case: UUID, request: Request) -> Response:
            context = RequestContext.new()
            if not csrf_valid(request):
                return _error(context, "CSRF_DENIED", 403)
            try:
                data = RecoveryCommand.model_validate(await _payload(request))
                token = SessionToken(request.cookies.get(SESSION, ""))
                identity = await asyncio.to_thread(sessions.resolve, token)
                rejection = await guard(
                    request, context, "staff:" + str(identity.user_id)
                )
                if rejection is not None:
                    return rejection
                capability = await asyncio.to_thread(
                    service.transition,
                    token,
                    case,
                    data.action,
                    data.operation_id,
                    context,
                    data.source_id,
                )
            except (ValueError, RecursionError):
                return _error(context, "INVALID_REQUEST", 400)
            except AccessDenied:
                return _error(context, "RECOVERY_DENIED", 404)
            except SQLAlchemyError:
                return _error(context, "SERVICE_UNAVAILABLE", 503)
            if capability is not None:
                return JSONResponse(
                    {"enrollment_capability": capability}, headers=HEADERS
                )
            return Response(status_code=204, headers=HEADERS)

        @router.post(
            "/auth/mfa/recovery/{case}/enrollment",
            openapi_extra=_body_schema(RecoveryEnrollment),
        )
        async def recovery_prepare(case: UUID, request: Request) -> Response:
            context = RequestContext.new()
            if not csrf_valid(request):
                return _error(context, "CSRF_DENIED", 403)
            try:
                data = RecoveryEnrollment.model_validate(await _payload(request))
                capability = data.capability.get_secret_value()
                rejection = await guard(
                    request, context, "prepare:" + str(case) + ":" + capability
                )
                if rejection is not None:
                    return rejection
                candidate, proof = await primary(
                    canonical_email(data.email),
                    data.password.get_secret_value(),
                    context,
                )
                seed = await asyncio.to_thread(
                    service.prepare,
                    case,
                    capability,
                    request.cookies.get(CSRF, ""),
                    candidate.user_id,
                    proof,
                )
            except (ValueError, RecursionError):
                return _error(context, "INVALID_REQUEST", 400)
            except AccessDenied:
                return _error(context, "RECOVERY_DENIED", 404)
            except (SQLAlchemyError, InvalidTag, KeyError, PasswordCapacityExceeded):
                return _error(context, "SERVICE_UNAVAILABLE", 503)
            return JSONResponse({"totp_seed": seed}, headers=HEADERS)

        @router.post(
            "/auth/mfa/recovery/{case}/complete",
            openapi_extra=_body_schema(RecoveryComplete),
        )
        async def recovery_finish(case: UUID, request: Request) -> Response:
            context = RequestContext.new()
            if not csrf_valid(request):
                return _error(context, "CSRF_DENIED", 403)
            try:
                data = RecoveryComplete.model_validate(await _payload(request))
                capability = data.capability.get_secret_value()
                rejection = await guard(
                    request, context, "complete:" + str(case) + ":" + capability
                )
                if rejection is not None:
                    return rejection
                codes = await asyncio.to_thread(
                    service.complete,
                    case,
                    capability,
                    request.cookies.get(CSRF, ""),
                    data.code.get_secret_value(),
                    context,
                )
            except (ValueError, RecursionError):
                return _error(context, "INVALID_REQUEST", 400)
            except AccessDenied:
                return _error(context, "RECOVERY_DENIED", 404)
            except (SQLAlchemyError, InvalidTag, KeyError):
                return _error(context, "SERVICE_UNAVAILABLE", 503)
            response = JSONResponse({"recovery_codes": codes}, headers=HEADERS)
            _clear(response)
            return response

    if mfa_recovery is not None:
        enable_recovery_workflow(mfa_recovery)

    if os.environ.get("VERIQ_ENABLE_TEST_ORGANIZATION_JOINING") == "1":
        joining = OrganizationJoining(engine)

        @router.post(
            "/organizations/{organization_id}/joining",
            openapi_extra=_body_schema(JoinCommand),
        )
        async def organization_join(
            organization_id: UUID, request: Request
        ) -> Response:
            context = RequestContext.new()
            if not csrf_valid(request):
                return _error(context, "CSRF_DENIED", 403)
            if request.client is None:
                return _error(context, "INVALID_REQUEST", 400)
            try:
                command = JoinCommand.model_validate(await _payload(request))
                token = SessionToken(request.cookies.get(SESSION, ""))
                gate = token._gate(joining.policy)
                await limiter.check(
                    AuthCategory.ORGANIZATION_JOIN,
                    trusted_client_ip(request.client.host, None, ()),
                    str(gate.session_id),
                )
                data = await asyncio.to_thread(
                    joining.execute, organization_id, token, command, context
                )
            except AuthLimitRejected as error:
                response = error.response(context)
                response.headers.update(HEADERS)
                return response
            except (ValueError, RecursionError):
                return _error(context, "INVALID_REQUEST", 400)
            except AccessDenied:
                return _error(context, "JOINING_DENIED", 404)
            except SQLAlchemyError:
                return _error(context, "SERVICE_UNAVAILABLE", 503)
            return JSONResponse(data, headers=HEADERS)

    if os.environ.get("VERIQ_ENABLE_TEST_BULK_IMPORT") == "1":
        imports = BulkImport(engine)
        upload_slots = asyncio.Semaphore(2)

        @router.post("/organizations/{organization_id}/imports/{action}")
        async def import_command(
            organization_id: UUID, action: str, request: Request
        ) -> Response:
            context = RequestContext.new()
            if not csrf_valid(request):
                return _error(context, "CSRF_DENIED", 403)
            if request.client is None:
                return _error(context, "INVALID_REQUEST", 400)
            try:
                token = SessionToken(request.cookies.get(SESSION, ""))
                gate = token._gate(imports.policy)
                await limiter.check(
                    AuthCategory.BULK_IMPORT,
                    trusted_client_ip(request.client.host, None, ()),
                    str(gate.session_id),
                )
                if action == "preview":
                    if upload_slots.locked():
                        return _error(context, "SERVICE_UNAVAILABLE", 503)
                    kind = {
                        "text/csv": "csv",
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xlsx",
                    }.get(
                        request.headers.get("content-type", "").split(";", 1)[0].lower()
                    )
                    column = request.query_params.get("email_column", "email")
                    if kind is None or len(column) > 64:
                        return _error(context, "INVALID_IMPORT_FORMAT", 400)
                    async with upload_slots:
                        await asyncio.to_thread(
                            imports.command,
                            organization_id,
                            token,
                            "authorize",
                            UUID(int=0),
                        )
                        payload = bytearray()
                        async with asyncio.timeout(5):
                            async for chunk in request.stream():
                                if len(payload) + len(chunk) > MAX_UPLOAD:
                                    return _error(context, "IMPORT_TOO_LARGE", 413)
                                payload.extend(chunk)
                        task = asyncio.create_task(
                            asyncio.to_thread(
                                imports.upload,
                                organization_id,
                                token,
                                bytes(payload),
                                kind,
                                column,
                            )
                        )
                        try:
                            result = await asyncio.shield(task)
                        except asyncio.CancelledError:
                            await asyncio.gather(task, return_exceptions=True)
                            raise
                elif action in {"confirm", "result", "claim"}:
                    data = await _payload(request)
                    if not isinstance(data, dict) or set(data) != (
                        {"batch_id", "version"} if action == "confirm" else {"batch_id"}
                    ):
                        raise ValueError("Invalid command fields")
                    if not isinstance(data["batch_id"], str):
                        raise ValueError("Invalid batch")
                    version = None
                    if action == "confirm":
                        if (
                            not isinstance(data["version"], str)
                            or len(data["version"]) != 64
                        ):
                            raise ValueError("Invalid version")
                        version = bytes.fromhex(data["version"])
                    result = await asyncio.to_thread(
                        imports.command,
                        organization_id,
                        token,
                        action,
                        UUID(data["batch_id"]),
                        version,
                    )
                else:
                    return _error(context, "IMPORT_DENIED", 404)
            except AuthLimitRejected as error:
                response = error.response(context)
                response.headers.update(HEADERS)
                return response
            except (ValueError, RecursionError, TimeoutError):
                return _error(context, "INVALID_IMPORT", 400)
            except AccessDenied:
                return _error(context, "IMPORT_DENIED", 404)
            except SQLAlchemyError:
                return _error(context, "SERVICE_UNAVAILABLE", 503)
            return JSONResponse(result, headers=HEADERS)

    if os.environ.get("VERIQ_ENABLE_TEST_ACADEMIC_CATALOG") == "1":
        catalog = AcademicCatalog(sessions)
        catalog_path = "/organizations/{organization_id}/academic/{kind}"

        @router.get(catalog_path, response_model=CatalogPage)
        async def catalog_read(
            organization_id: UUID,
            kind: CatalogKind,
            request: Request,
            archived: bool = False,
            query: str = Query(default="", max_length=160),
            page: int = Query(default=1, ge=1, le=10000),
        ) -> Response:
            context = RequestContext.new()
            try:
                result = await asyncio.to_thread(
                    catalog.read,
                    SessionToken(request.cookies.get(SESSION, "")),
                    organization_id,
                    kind,
                    None,
                    archived,
                    query,
                    page,
                )
            except AccessDenied:
                return _error(context, "CATALOG_DENIED", 404)
            except SQLAlchemyError:
                return _error(context, "SERVICE_UNAVAILABLE", 503)
            return JSONResponse(result.model_dump(mode="json"), headers=HEADERS)

        @router.get(catalog_path + "/{item_id}", response_model=CatalogRow)
        async def catalog_card(
            organization_id: UUID,
            kind: CatalogKind,
            item_id: UUID,
            request: Request,
        ) -> Response:
            context = RequestContext.new()
            try:
                result = await asyncio.to_thread(
                    catalog.read,
                    SessionToken(request.cookies.get(SESSION, "")),
                    organization_id,
                    kind,
                    item_id,
                    False,
                    "",
                    1,
                )
            except AccessDenied:
                return _error(context, "CATALOG_DENIED", 404)
            except SQLAlchemyError:
                return _error(context, "SERVICE_UNAVAILABLE", 503)
            return JSONResponse(result.model_dump(mode="json"), headers=HEADERS)

        async def catalog_write(
            organization_id: UUID,
            kind: CatalogKind,
            item_id: UUID | None,
            request: Request,
            schema: type[CatalogInput] | type[CatalogArchive],
        ) -> Response:
            context = RequestContext.new()
            if not csrf_valid(request):
                return _error(context, "CSRF_DENIED", 403)
            try:
                if item_id is None:
                    item_id = UUID(request.headers.get("Idempotency-Key", ""))
                result = await asyncio.to_thread(
                    catalog.write,
                    SessionToken(request.cookies.get(SESSION, "")),
                    organization_id,
                    kind,
                    item_id,
                    schema.model_validate(await _payload(request)),
                    context.request_id,
                )
            except (ValueError, RecursionError):
                return _error(context, "INVALID_REQUEST", 400)
            except AccessDenied:
                return _error(context, "CATALOG_DENIED", 404)
            except CatalogConflict:
                return _error(context, "CATALOG_CONFLICT", 409)
            except SQLAlchemyError:
                return _error(context, "SERVICE_UNAVAILABLE", 503)
            return JSONResponse(result.model_dump(mode="json"), headers=HEADERS)

        @router.post(
            catalog_path,
            response_model=CatalogRow,
            openapi_extra=_body_schema(CatalogInput),
        )
        async def catalog_create(
            organization_id: UUID, kind: CatalogKind, request: Request
        ) -> Response:
            return await catalog_write(
                organization_id, kind, None, request, CatalogInput
            )

        @router.patch(
            catalog_path + "/{item_id}",
            response_model=CatalogRow,
            openapi_extra=_body_schema(CatalogEdit),
        )
        async def catalog_edit(
            organization_id: UUID, kind: CatalogKind, item_id: UUID, request: Request
        ) -> Response:
            return await catalog_write(
                organization_id, kind, item_id, request, CatalogEdit
            )

        @router.post(
            catalog_path + "/{item_id}/archive",
            response_model=CatalogRow,
            openapi_extra=_body_schema(CatalogArchive),
        )
        async def catalog_archive(
            organization_id: UUID, kind: CatalogKind, item_id: UUID, request: Request
        ) -> Response:
            return await catalog_write(
                organization_id, kind, item_id, request, CatalogArchive
            )

        @router.post(
            catalog_path + "/{item_id}/restore",
            response_model=CatalogRow,
            openapi_extra=_body_schema(CatalogRestore),
        )
        async def catalog_restore(
            organization_id: UUID, kind: CatalogKind, item_id: UUID, request: Request
        ) -> Response:
            return await catalog_write(
                organization_id, kind, item_id, request, CatalogRestore
            )

    return router
