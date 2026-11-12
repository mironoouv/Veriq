from uuid import UUID

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError

from veriq.main import create_app

LIVE = "/api/v1/health/live"
READY = "/api/v1/health/ready"


def test_healthy_database() -> None:
    database = create_engine("sqlite://")
    with TestClient(create_app(engine=database, enable_docs=True)) as client:
        assert client.get(LIVE).json() == {"status": "ok"}
        result = client.get(READY)
        assert result.status_code == 200
        assert result.json() == {"status": "ok"}
        schema = client.get("/api/v1/openapi.json").json()
        assert set(schema["paths"][READY]["get"]["responses"]) == {"200", "503"}


def test_unavailable_database_has_redacted_response() -> None:
    def unavailable() -> None:
        raise OperationalError(
            None, None, RuntimeError("private database configuration")
        )

    database = create_engine("sqlite://", creator=unavailable)
    with TestClient(create_app(engine=database, enable_docs=False)) as client:
        assert client.get(LIVE).status_code == 200
        result = client.get(READY)
        assert result.status_code == 503
        assert result.headers["Cache-Control"] == "no-store"
        error = result.json()["error"]
        assert error["code"] == "DEPENDENCY_UNAVAILABLE"
        UUID(error["request_id"])
        assert "private database configuration" not in result.text
        assert client.get("/api/v1/docs").status_code == 404
        assert client.get("/api/v1/openapi.json").status_code == 404
