# CentralSOC v1.0 — Release candidate gate (NOT production approval)

Scope is **frozen**: CSV/reporting, security review, end-to-end tests, deployment readiness. No new dashboards or detection features until these gates are closed.

## Verified in this increment

- Existing alert handoff CSV is bounded to 1,000 filtered records, permission-gated, sanitized against spreadsheet formula execution and audited.
- General reports are bounded to 5,000 records, permission-gated and now audited with no-store and nosniff response headers.
- Incident CSV is bounded to 1,000 records, permission-gated and now audited with no-store and nosniff headers.
- `/healthz` is process liveness; new `/readyz` checks that the configured database responds to `SELECT 1`, returning HTTP 503 on failure without displaying connection details.
- Database transaction teardown rolls back HTTP 4xx/5xx requests. This is *not* a guarantee against every partial commit or concurrent transaction race.

## Open release blockers

1. Run **all** Flask/browser tests using installed dependencies on a clean, isolated Windows environment. The current build environment lacks Flask. Verify login, CSRF, permissions for ADMIN/ANALYST/VIEWER, exports (including denied attempts), uploads, phishing cases, alert acknowledgement and the end-to-end incident workflow.
2. Confirm `python -m alembic current -v` shows the same head as `python -m alembic heads` on the **correct existing database**; create a verified backup before any upgrade. Verify rollback/restore in an isolated copy.
3. Test PostgreSQL migrations and concurrent analyst operations. SQLite is only the supported local-development baseline at present.
4. Review deployment reverse-proxy trust, HTTPS, secure cookies, environment isolation, account provisioning, rate limits, log retention, backup/restore and disaster recovery. Perform authorized application security tests.
5. Run representative performance tests and document maximum supported upload size, throughput and query latency.
6. Add integration tests for `/readyz` returning 200/503, report-export audit persistence, and forbidden export requests. Static tests alone do not prove route behavior.

## Windows local validation

In your **existing working project directory** after backing up `.env`, `instance/`, the SQLite DB and uploads:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m alembic heads
python -m alembic current -v
python -m pytest -q
$env:REGEXSOC_ENV = "development"
python run.py
```

Use `http://127.0.0.1:5000/healthz` and `/readyz`. Do **not** point new extracted copies at existing production data without checking configuration. Do not re-create an admin account if the database already contains users.

## Deployment candidate guidance

- Use a non-debug WSGI server behind HTTPS with a fixed, strong `REGEXSOC_SECRET_KEY`, `REGEXSOC_ENV=production`, a private database, and server-managed secrets.
- On Windows consider Waitress, after separate installation and verification. The command below is an example only, **not a tested production deployment**:

```powershell
python -m pip install "waitress>=3,<4"
$env:REGEXSOC_ENV = "production"
# Set REGEXSOC_SECRET_KEY and DATABASE_URL through a secure deployment mechanism.
waitress-serve --listen=127.0.0.1:8080 --call regexsoc.web:create_app
```

- Put a TLS-terminating reverse proxy in front of Waitress. Verify proxy headers and Flask `request.is_secure` handling before enabling external access; secure session cookies are enabled in production. Never run `python run.py` on the public Internet.
- Exports contain sensitive operational context. Share only via an approved internal channel, enforce least privilege, and apply the organization's retention policies.

**Status:** development release candidate; production readiness remains **NOT VERIFIED**.
