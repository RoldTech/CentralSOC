"""Read-only local setup checks for CentralSOC.

Run ``python -m regexsoc.doctor`` from the project root. This module uses only
Python's standard library and never creates a database or prints secret values.
"""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from urllib.parse import unquote, urlsplit


def inspect_setup(root: Path, environ: dict[str, str] | None = None) -> list[tuple[str, str]]:
    """Return (level, message) pairs without modifying the filesystem."""
    env = dict(os.environ if environ is None else environ)
    config_file = root / '.env'
    if config_file.is_file():
        # Respect already-set environment variables, like python-dotenv.
        for line in config_file.read_text(encoding='utf-8-sig').splitlines():
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, value = line.split('=', 1)
            key = key.strip()
            if key and key not in env:
                env[key] = value.strip().strip('"').strip("'")
    results: list[tuple[str, str]] = []
    if not config_file.is_file():
        results.append(('WARN', 'Missing .env file; local configuration may not persist.'))
    else:
        results.append(('OK', 'Local .env file found.'))
    if env.get('REGEXSOC_ENV', '').lower() != 'development':
        results.append(('WARN', 'REGEXSOC_ENV is not development; built-in local server will refuse startup.'))
    else:
        results.append(('OK', 'Local development mode configured.'))
    if not env.get('REGEXSOC_SECRET_KEY', '').strip():
        results.append(('WARN', 'No persistent REGEXSOC_SECRET_KEY configured; sessions may reset on restart.'))
    else:
        results.append(('OK', 'Session secret configured (value hidden).'))
    db_url = env.get('DATABASE_URL', 'sqlite:///instance/regexsoc.db')
    if not db_url.startswith('sqlite:///'):
        results.append(('INFO', 'Database is not a file-based SQLite URL; inspect its connection separately.'))
        return results
    database = unquote(db_url[len('sqlite:///'):].split('?', 1)[0])
    if database == ':memory:':
        results.append(('WARN', 'In-memory database does not persist across process restarts.'))
        return results
    path = Path(database)
    if not path.is_absolute():
        path = root / path
    if not path.is_file():
        results.append(('WARN', f'Database file not found: {path}. Do not initialize if your existing database is elsewhere.'))
        return results
    try:
        # SQLite read-only mode prevents accidental creation or schema changes.
        uri = f'{path.resolve().as_uri()}?mode=ro'
        with sqlite3.connect(uri, uri=True) as connection:
            table_names = {r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if 'alembic_version' in table_names:
                revision = connection.execute('SELECT version_num FROM alembic_version').fetchone()
                results.append(('OK', f'Database found; Alembic revision: {revision[0] if revision else "missing"}.'))
            else:
                results.append(('WARN', 'Database exists but has no Alembic version table; follow existing-database migration guidance.'))
    except (sqlite3.Error, OSError) as exc:
        results.append(('WARN', f'Database could not be inspected read-only ({type(exc).__name__}).'))
    return results


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    report = inspect_setup(root)
    print('CentralSOC local setup check (read-only)')
    for level, message in report:
        print(f'[{level}] {message}')
    return 1 if any(level == 'WARN' for level, _ in report) else 0


if __name__ == '__main__':
    raise SystemExit(main())
