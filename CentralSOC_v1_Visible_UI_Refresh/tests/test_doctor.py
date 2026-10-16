"""Read-only diagnostic regressions."""
import sqlite3
from pathlib import Path

from regexsoc.doctor import inspect_setup


def test_missing_database_not_created(tmp_path):
    db = tmp_path / 'missing.db'
    report = inspect_setup(tmp_path, {'REGEXSOC_ENV': 'development', 'REGEXSOC_SECRET_KEY': 'test', 'DATABASE_URL': f'sqlite:///{db}'})
    assert any('Database file not found' in msg for _, msg in report)
    assert not db.exists()


def test_existing_database_revision_read_only(tmp_path):
    db = tmp_path / 'existing.db'
    with sqlite3.connect(db) as conn:
        conn.execute('CREATE TABLE alembic_version (version_num TEXT)')
        conn.execute("INSERT INTO alembic_version VALUES ('b72cf9d2e501')")
    before = db.read_bytes()
    (tmp_path / '.env').write_text('REGEXSOC_ENV=development\nREGEXSOC_SECRET_KEY=local-only\nDATABASE_URL=sqlite:///existing.db\n')
    report = inspect_setup(tmp_path, {})
    assert any('b72cf9d2e501' in msg for _, msg in report)
    assert db.read_bytes() == before


def test_secrets_never_in_messages(tmp_path):
    secret = 'never-display-this-token'
    report = inspect_setup(tmp_path, {'REGEXSOC_SECRET_KEY': secret})
    assert secret not in repr(report)


def test_existing_database_without_migrations_not_stamped(tmp_path):
    db = tmp_path / 'legacy.db'
    with sqlite3.connect(db) as conn:
        conn.execute('CREATE TABLE retained (id INTEGER)')
    report = inspect_setup(tmp_path, {'DATABASE_URL': f'sqlite:///{db}'})
    assert any('no Alembic version table' in msg for _, msg in report)
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT name FROM sqlite_master WHERE name='alembic_version'").fetchone() is None
