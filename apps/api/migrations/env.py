from alembic import context

from veriq.database import create_database_engine, database_url


def run_migrations() -> None:
    if context.is_offline_mode():
        context.configure(
            dialect_name=database_url().get_backend_name(), literal_binds=True
        )
        with context.begin_transaction():
            context.run_migrations()
        return

    engine = create_database_engine()
    try:
        with engine.connect() as connection:
            context.configure(connection=connection)
            with context.begin_transaction():
                context.run_migrations()
    finally:
        engine.dispose()


run_migrations()
