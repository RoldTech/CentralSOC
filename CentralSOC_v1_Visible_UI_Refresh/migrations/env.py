"""Alembic environment: use the application's database URL and ORM metadata."""
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool

from regexsoc import config as app_config
from regexsoc.db.models import Base
from regexsoc.db.session import make_engine


def database_url() -> str:
    return alembic_config.attributes.get("connection_url_verified") or app_config.database_url()

alembic_config = context.config
if alembic_config.config_file_name is not None:
    fileConfig(alembic_config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=database_url(), target_metadata=target_metadata,
        literal_binds=True, dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = make_engine(database_url())
    try:
        with engine.connect() as connection:
            context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
            with context.begin_transaction():
                context.run_migrations()
    finally:
        engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
