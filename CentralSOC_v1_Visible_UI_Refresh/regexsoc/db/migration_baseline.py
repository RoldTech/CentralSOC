"""Safely adopt an existing RegexSOC database into Alembic migration tracking.

Run only after taking a verified database backup. Never alters application tables.
"""
from __future__ import annotations

import sys
from pathlib import Path

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import inspect

from regexsoc.db.models import Base
from regexsoc.db.session import make_engine


def stamp_existing_database(url: str, ini_path: str | Path) -> None:
    """Stamp an *exactly matching* legacy schema; refuse empty or divergent schemas."""
    engine = make_engine(url)
    try:
        with engine.connect() as connection:
            inspector = inspect(connection)
            tables = set(inspector.get_table_names())
            expected = set(Base.metadata.tables)
            if "alembic_version" in tables:
                raise RuntimeError("Database is already version-tracked; use 'alembic upgrade head'.")
            if tables != expected:
                raise RuntimeError(
                    f"Schema mismatch: missing={sorted(expected - tables)}, "
                    f"unexpected={sorted(tables - expected)}. No changes made."
                )
            differences = compare_metadata(MigrationContext.configure(connection), Base.metadata)
            if differences:
                raise RuntimeError(
                    f"Schema differs from ORM metadata ({len(differences)} differences); "
                    "review database and migrations manually. No changes made."
                )
        cfg = Config(str(Path(ini_path).resolve()))
        cfg.attributes["connection_url_verified"] = url
        # Alembic's env.py gets its URL through DATABASE_URL; avoid modifying
        # process-global environment by temporarily setting a config attribute.
        command.stamp(cfg, "head")
    finally:
        engine.dispose()


def main() -> int:
    from regexsoc import config

    ini_path = Path(__file__).resolve().parents[2] / "alembic.ini"
    try:
        stamp_existing_database(config.database_url(), ini_path)
    except Exception as exc:
        print(f"Baseline adoption refused: {exc}", file=sys.stderr)
        return 1
    print("Existing database stamped at Alembic head without modifying application tables.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
