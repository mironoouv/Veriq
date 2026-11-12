"""Test-only HTTP adapter for registration and email verification."""

import asyncio
import json
import os
import re
import secrets
from hashlib import sha256
from pathlib import Path
from uuid import UUID, uuid4

from cryptography.fernet import Fernet
from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from redis.asyncio import Redis
from sqlalchemy import Engine, text
from sqlalchemy.exc import SQLAlchemyError
from starlette.responses import HTMLResponse, JSONResponse, Response

from veriq.auth_audit import AuthEvent, AuthResult, RequestContext, append_attempt
from veriq.auth_rate_limit import (
    AuthCategory,
    AuthLimitRejected,
    AuthRateLimiter,
    LimitBudget,
    trusted_client_ip,
)
from veriq.registration_policy import PasswordPolicy, canonical_email
from veriq.verification_mail import VerificationMail

_PATH = "/api/v1/auth"
_PROOF = re.compile(r"([0-9a-f]{32})\.[A-Za-z0-9_-]{43}")
_HEADERS = {"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"}


class Address(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    email: str = Field(max_length=320)


class Signup(Address):
    password: SecretStr


class Verify(Signup):
    proof: SecretStr


def registration_enabled() -> bool:
    return (
        os.environ.get("VERIQ_ENV") == "test"
        and os.environ.get("VERIQ_ENABLE_TEST_REGISTRATION") == "1"
    )


def _error(context: RequestContext, code: str, status: int) -> JSONResponse:
    return JSONResponse(
        {
            "error": {
                "code": code,
                "message": "Request could not be completed.",
                "request_id": str(context.request_id),
                "details": {},
            }
        },
        status_code=status,
        headers=_HEADERS,
    )


async def _payload(request: Request) -> object:
    if (
        request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        != "application/json"
    ):
        raise ValueError("JSON required")
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > 8192:
            raise ValueError("Payload too large")
        body.extend(chunk)
    return json.loads(body)


def _write(
    engine: Engine,
    cipher: Fernet,
    category: AuthCategory,
    email: str,
    password_hash: str | None,
    proof: str | None,
    context: RequestContext,
) -> bool:
    with engine.begin() as connection:
        accepted = True
        if category == AuthCategory.EMAIL_VERIFY:
            match = _PROOF.fullmatch(proof or "")
            accepted = match is not None and bool(
                connection.execute(
                    text(
                        "SELECT public.veriq_signup_verify(:id, :digest, :email, :password)"
                    ),
                    {
                        "id": UUID(hex=match[1]),
                        "digest": sha256((proof or "").encode("ascii")).digest(),
                        "email": email,
                        "password": password_hash,
                    },
                ).scalar_one()
            )
        else:
            proof_id = uuid4()
            token = f"{proof_id.hex}.{secrets.token_urlsafe(32)}"
            params = {
                "email": email,
                "id": proof_id,
                "digest": sha256(token.encode("ascii")).digest(),
                "envelope": VerificationMail(email, token).seal(cipher),
            }
            if category == AuthCategory.REGISTRATION:
                connection.execute(
                    text(
                        "SELECT public.veriq_signup_start(:user, :email, :password, :id, :digest, :envelope)"
                    ),
                    {**params, "user": uuid4(), "password": password_hash},
                )
            else:
                connection.execute(
                    text(
                        "SELECT public.veriq_signup_resend(:email, :id, :digest, :envelope)"
                    ),
                    params,
                )
        append_attempt(
            connection,
            uuid4(),
            context,
            AuthEvent.REGISTRATION,
            AuthResult.SUCCEEDED if accepted else AuthResult.DENIED,
        )
    return accepted


def _body_schema(model: type[BaseModel]) -> dict[str, object]:
    return {
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": model.model_json_schema()}},
        }
    }


def registration_router(engine: Engine, redis: Redis) -> APIRouter:
    cipher = Fernet(os.environ["VERIQ_TEST_MAIL_KEY"].encode("ascii"))
    passwords = PasswordPolicy(Path(os.environ["VERIQ_TEST_PASSWORD_BLOCKLIST"]))
    limiter = AuthRateLimiter(
        redis,
        bytes.fromhex(os.environ["VERIQ_TEST_AUTH_HMAC_KEY"]),
        {
            category: LimitBudget(
                30, 3 if category == AuthCategory.EMAIL_RESEND else 10, 300
            )
            for category in AuthCategory
        },
    )
    # Reject excess local work before entering the thread pool. A cancellation
    # must not free the slot while a native Argon2 operation is still running.
    active: set[asyncio.Task[str]] = set()
    router = APIRouter(prefix=_PATH, tags=["auth-test"])

    async def handle(request: Request, category: AuthCategory) -> Response:
        context = RequestContext.new()
        try:
            payload = await _payload(request)
            data: Address
            if category == AuthCategory.REGISTRATION:
                data = Signup.model_validate(payload)
            elif category == AuthCategory.EMAIL_VERIFY:
                data = Verify.model_validate(payload)
            else:
                data = Address.model_validate(payload)
            email = canonical_email(data.email)
            if request.client is None:
                raise ValueError("Missing peer")
            # The explicitly enabled test adapter is direct-peer only.
            ip = trusted_client_ip(request.client.host, None, ())
        except (ValueError, RecursionError):
            return _error(context, "INVALID_REQUEST", 400)

        try:
            await limiter.check(category, ip, email)
        except AuthLimitRejected as error:
            response = error.response(context)
            response.headers.update(_HEADERS)
            return response

        password_hash = None
        proof = data.proof.get_secret_value() if isinstance(data, Verify) else None
        if isinstance(data, Signup):
            if len(active) >= 2:
                return _error(context, "SERVICE_UNAVAILABLE", 503)
            task = asyncio.create_task(
                asyncio.to_thread(passwords.hash, data.password.get_secret_value())
            )
            active.add(task)
            task.add_done_callback(active.discard)
            try:
                password_hash = await asyncio.shield(task)
            except ValueError:
                return _error(context, "PASSWORD_REJECTED", 400)
        try:
            accepted = await asyncio.to_thread(
                _write, engine, cipher, category, email, password_hash, proof, context
            )
        except SQLAlchemyError:
            return _error(context, "SERVICE_UNAVAILABLE", 503)
        if not accepted:
            return _error(context, "INVALID_PROOF", 400)
        return Response(
            status_code=204 if category == AuthCategory.EMAIL_VERIFY else 202,
            headers={**_HEADERS, "X-Request-ID": str(context.request_id)},
        )

    @router.post("/register", status_code=202, openapi_extra=_body_schema(Signup))
    async def register(request: Request) -> Response:
        return await handle(request, AuthCategory.REGISTRATION)

    @router.post(
        "/resend-verification", status_code=202, openapi_extra=_body_schema(Address)
    )
    async def resend(request: Request) -> Response:
        return await handle(request, AuthCategory.EMAIL_RESEND)

    @router.post("/verify-email", status_code=204, openapi_extra=_body_schema(Verify))
    async def verify(request: Request) -> Response:
        return await handle(request, AuthCategory.EMAIL_VERIFY)

    @router.get("/verify-email", include_in_schema=False)
    async def verification_page() -> HTMLResponse:
        nonce = secrets.token_urlsafe(24)
        return HTMLResponse(
            f"""<!doctype html><html lang="en"><meta charset="utf-8">
            <title>Verify email</title>
            <form><label>Email <input type="email" name="email" required></label>
            <label>Set password <input type="password" name="password"
                autocomplete="new-password" required></label>
            <button type="button">Verify email</button></form><output></output>
            <script nonce="{nonce}">
            const proof = location.hash.slice(1);
            history.replaceState(null, "", location.pathname);
            const form = document.querySelector("form");
            form.addEventListener("submit", (event) => event.preventDefault());
            form.querySelector("button").onclick = async () => {{
              if (!form.reportValidity()) return;
              const values = Object.fromEntries(new FormData(form));
              const output = document.querySelector("output");
              try {{
                const result = await fetch(location.pathname, {{
                  method: "POST", credentials: "omit",
                  headers: {{"Content-Type": "application/json"}},
                  body: JSON.stringify({{...values, proof}})
                }});
                output.textContent = result.ok ? "Email verified." : "Verification failed.";
                if (result.ok) form.reset();
              }} catch {{ output.textContent = "Verification unavailable."; }}
            }};
            </script></html>""",
            headers={
                **_HEADERS,
                "Content-Security-Policy": (
                    f"default-src 'none'; script-src 'nonce-{nonce}'; connect-src 'self'; "
                    "form-action 'none'; base-uri 'none'; frame-ancestors 'none'"
                ),
                "X-Content-Type-Options": "nosniff",
            },
        )

    return router
