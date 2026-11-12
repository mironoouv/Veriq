import os

from sqlalchemy import URL, Engine, create_engine


def database_url() -> URL:
    return URL.create(
        "postgresql+psycopg",
        username=os.environ["VERIQ_DB_USER"],
        password=os.environ["VERIQ_DB_PASSWORD"],
        host=os.environ["VERIQ_DB_HOST"],
        port=int(os.environ.get("VERIQ_DB_PORT", "5432")),
        database=os.environ["VERIQ_DB_NAME"],
    )


def create_database_engine(url: URL | None = None) -> Engine:
    return create_engine(
        url if url is not None else database_url(),
        pool_pre_ping=True,
        hide_parameters=True,
        connect_args={"connect_timeout": 2},
    )
