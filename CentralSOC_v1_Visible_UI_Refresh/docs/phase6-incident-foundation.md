# Phase 6 — Incident persistence foundation

## Implemented

- `Incident` ORM with lifecycle status, owner, severity, resolution, timestamps, and originating analyst.
- `IncidentAlert` relational table linking multiple alerts to incidents without rewriting alert records.
- Alembic revision `b72cf9d2e501` (depends on Phase 2 baseline).
- Transactional services in `regexsoc/db/incidents.py` for case creation, assignment, alert linking, notes and status changes.
- Audit records for incident activity; redundant alert links are idempotent.
- Enforced transitions; resolving or closing a case requires a recorded resolution. `Contained` is a **manual status**, not evidence of an executed containment action.
- Service-layer validation and rollback regression tests.

## Operations

After backing up your database, follow `docs/phase2-database-migrations.md` to validate/stamp existing SQLite installations; then run `alembic upgrade head` with the project's configured `REGEXSOC_DATABASE_URL` (see `migrations/env.py`). Do not stamp a mismatched schema. Never apply `alembic downgrade` to production data without backups; downgrading this revision drops incident records.

## Tests performed

- `pytest -q tests/test_incidents.py tests/test_migrations.py` — 6 passing tests.
- `pytest -q --ignore=tests/test_web_app.py --ignore=tests/test_dashboard_pages.py --ignore=tests/test_security_headers_flask.py` — passing, see accompanying test output.
- Alembic upgrade from empty SQLite database to head — confirmed `incidents` and `incident_alerts` tables created.

## Limitations and next increment

This is a **database/service foundation**. No incident web routes or RBAC-protected UI are wired yet. Server-side permission checks must be added to future endpoints before services are exposed to user input. Flask-dependent integration tests remain unavailable in this environment. Existing audit logs are not tamper-proof. No automatic containment is implemented. PostgreSQL migration testing and concurrency testing remain outstanding.
