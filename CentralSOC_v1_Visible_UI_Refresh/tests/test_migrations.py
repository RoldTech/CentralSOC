"""Migration creation, schema parity and safe adoption of a legacy database."""
import pytest

pytest.importorskip("alembic")
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text, insert

from regexsoc.db.migration_baseline import stamp_existing_database
from regexsoc.db.models import Base, AuditLog
from regexsoc.db.session import init_db


def cfg(tmp_path):
    from pathlib import Path
    ini = Path(__file__).resolve().parents[1] / "alembic.ini"
    config = Config(str(ini))
    config.attributes["connection_url_verified"] = f"sqlite:///{tmp_path / 'new.db'}"
    return ini, config


def test_migration_on_empty_database_matches_models(tmp_path):
    _, config = cfg(tmp_path)
    command.upgrade(config, "head")
    engine = create_engine(config.attributes["connection_url_verified"])
    with engine.connect() as connection:
        assert not compare_metadata(MigrationContext.configure(connection), Base.metadata)
        assert "alembic_version" in inspect(connection).get_table_names()
    engine.dispose()


def test_existing_database_can_be_stamped_without_data_loss(tmp_path):
    ini, config = cfg(tmp_path)
    url = config.attributes["connection_url_verified"]
    engine = create_engine(url)
    init_db(engine)
    with engine.begin() as connection:
        connection.execute(insert(AuditLog).values(username="test", action="baseline", result="OK"))
    engine.dispose()
    stamp_existing_database(url, ini)
    with create_engine(url).connect() as connection:
        assert connection.scalar(text("SELECT COUNT(*) FROM audit_log")) == 1
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) is not None


def test_incomplete_schema_is_refused(tmp_path):
    ini, config = cfg(tmp_path)
    url = config.attributes["connection_url_verified"]
    with create_engine(url).begin() as connection:
        connection.execute(text("CREATE TABLE audit_log (id INTEGER PRIMARY KEY)"))
    with pytest.raises(RuntimeError, match="Schema mismatch"):
        stamp_existing_database(url, ini)
    assert "alembic_version" not in inspect(create_engine(url)).get_table_names()


def test_operations_upgrade_preserves_existing_data(tmp_path):
    _, config = cfg(tmp_path)
    command.upgrade(config, 'ae72c08d4e31')
    engine = create_engine(config.attributes['connection_url_verified'])
    with engine.begin() as connection:
        connection.execute(insert(AuditLog).values(username='preserve', action='before_upgrade', result='SUCCESS'))
    command.upgrade(config, 'head')
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT COUNT(*) FROM audit_log WHERE username='preserve'")) == 1
        assert 'response_runs' in inspect(connection).get_table_names()
        assert not compare_metadata(MigrationContext.configure(connection), Base.metadata)
    engine.dispose()
