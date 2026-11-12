import asyncio
import os
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Literal
from uuid import uuid4

from fastapi import FastAPI, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from redis.exceptions import RedisError
from sqlalchemy import Engine, text
from sqlalchemy.exc import SQLAlchemyError

from veriq.database import create_database_engine
from veriq.redis_client import create_redis, ping_redis
from veriq.registration import registration_enabled, registration_router


class Health(BaseModel):
    status: Literal["ok"] = "ok"


class HealthError(BaseModel):
    code: Literal["DEPENDENCY_UNAVAILABLE"] = "DEPENDENCY_UNAVAILABLE"
    message: str = "Dependency unavailable"
    request_id: str
    details: dict[str, str] = Field(default_factory=dict)


class HealthFailure(BaseModel):
    error: HealthError


def create_app(
    *,
    engine: Engine | None = None,
    enable_docs: bool | None = None,
    check_redis: Callable[[], object] | None = None,
) -> FastAPI:
    database = engine if engine is not None else create_database_engine()
    cache = create_redis() if check_redis is None else None
    if enable_docs is None:
        enable_docs = os.environ.get("VERIQ_ENV") == "development"

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            database.dispose()
            if cache is not None:
                await cache.aclose()

    def check_database() -> None:
        with database.connect() as connection:
            connection.execute(text("SELECT 1"))

    prefix = "/api/v1"
    app = FastAPI(
        title="Veriq API",
        version="0.1.0",
        docs_url=f"{prefix}/docs" if enable_docs else None,
        openapi_url=f"{prefix}/openapi.json" if enable_docs else None,
        redoc_url=None,
        lifespan=lifespan,
    )

    @app.get(f"{prefix}/health/live", operation_id="healthLive")
    def liveness() -> Health:
        return Health()

    @app.get(
        f"{prefix}/health/ready",
        operation_id="healthReady",
        response_model=Health,
        responses={
            503: {"model": HealthFailure, "description": "Dependency unavailable"}
        },
    )
    async def readiness(response: Response) -> Health | JSONResponse:
        response.headers["Cache-Control"] = "no-store"
        try:
            await asyncio.to_thread(check_database)
            if cache is not None:
                await ping_redis(cache)
            elif check_redis is not None:
                check_redis()
        except (SQLAlchemyError, RedisError, TimeoutError):
            failure = HealthFailure(error=HealthError(request_id=str(uuid4())))
            return JSONResponse(
                status_code=503,
                content=failure.model_dump(mode="json"),
                headers={"Cache-Control": "no-store"},
            )
        return Health()

    if cache is not None and registration_enabled():
        app.include_router(registration_router(database, cache))

    return app
