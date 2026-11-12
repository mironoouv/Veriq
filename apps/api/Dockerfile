FROM ghcr.io/astral-sh/uv:0.13.7 AS uv
FROM python:3.11.15-slim-bookworm AS base
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_PYTHON_DOWNLOADS=never PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev
COPY alembic.ini ./
COPY migrations migrations
COPY veriq veriq
ENV PATH="/app/.venv/bin:$PATH"

FROM base AS checks
COPY tests tests
RUN uv sync --locked
RUN ruff format --check . && ruff check . && mypy . && pytest

FROM base AS runtime
USER 10001:10001
CMD ["uvicorn", "veriq.main:create_app", "--factory", "--host", "0.0.0.0", "--no-access-log"]
