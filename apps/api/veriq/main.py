import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Literal
from uuid import uuid4

from fastapi import FastAPI, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import Engine, text
from sqlalchemy.exc import SQLAlchemyError

from veriq.database import create_database_engine


class Health(BaseModel):
    status: Literal["ok"] = "ok"


class HealthError(BaseModel):
    code: Literal["DEPENDENCY_UNAVAILABLE"] = "DEPENDENCY_UNAVAILABLE"
    message: str = "Database unavailable"
    request_id: str
    details: dict[str, str] = Field(default_factory=dict)


class HealthFailure(BaseModel):
    error: HealthError


def create_app(
    *, engine: Engine | None = None, enable_docs: bool | None = None
) -> FastAPI:
    database = engine if engine is not None else create_database_engine()
    if enable_docs is None:
        enable_docs = os.environ.get("VERIQ_ENV") == "development"

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            database.dispose()

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
            503: {"model": HealthFailure, "description": "Database unavailable"}
        },
    )
    def readiness(response: Response) -> Health | JSONResponse:
        response.headers["Cache-Control"] = "no-store"
        try:
            with database.connect() as connection:
                connection.execute(text("SELECT 1"))
        except SQLAlchemyError:
            failure = HealthFailure(error=HealthError(request_id=str(uuid4())))
            return JSONResponse(
                status_code=503,
                content=failure.model_dump(mode="json"),
                headers={"Cache-Control": "no-store"},
            )
        return Health()

    return app
