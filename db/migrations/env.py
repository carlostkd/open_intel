"""
Alembic migration environment.

DATABASE_URL is read from the environment (via config.py) so credentials
are never stored in version control.  The models' Base.metadata is imported
here so `alembic revision --autogenerate` can diff the ORM against the DB.
"""

import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# Make sure the project root is on sys.path so `from db.models import Base`
# resolves correctly regardless of where alembic is invoked from.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from config import DATABASE_URL  # noqa: E402
from db.models import Base       # noqa: E402  — imports all mapped classes

# Alembic Config object (gives access to alembic.ini values)
config = context.config

# Override sqlalchemy.url with the value from the environment.
# This means alembic.ini never needs a real connection string.
if DATABASE_URL:
    config.set_main_option("sqlalchemy.url", DATABASE_URL)

# Set up Python logging from alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# This is what autogenerate inspects to build migration scripts.
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """
    Run migrations without a live DB connection.
    Emits SQL to stdout — useful for review or for DBAs who apply migrations manually.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """
    Run migrations against a live DB connection.
    This is the normal path for `alembic upgrade head`.
    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,  # no pooling needed for one-shot migration runs
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,        # detect column type changes in autogenerate
            compare_server_default=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
