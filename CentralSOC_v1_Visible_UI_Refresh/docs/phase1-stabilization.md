# CentralSOC / RegexSOC — Phase 1 stabilization record

## Scope

Incremental modifications to the supplied RegexSOC archive. No database reset, destructive migration, or application rewrite performed.

## Changes

- `requirements.txt`: preserves Phase 0 declarations for Flask, argon2-cffi and pyotp.
- `regexsoc/web/__init__.py`: imports Flask inside `create_app`, allowing framework-independent web helpers to be imported without Flask. Tracks unsuccessful HTTP responses and rolls back pending SQLAlchemy writes on responses >=400, including handled errors. Preserves commits for successful responses and for intentional 3xx redirects (important for login failure counters).
- `regexsoc/security/csrf.py`: rejects noncanonical base64url encodings of signed CSRF token parts before validating signature, expiration and session binding.
- `tests/test_web_app.py`: adds a regression test ensuring a handled HTTP 400 does not persist changes to a user record.

## Validation performed

From repository root:

```bash
python -m compileall -q regexsoc tests
python -m pytest -q --ignore=tests/test_web_app.py --ignore=tests/test_dashboard_pages.py --ignore=tests/test_security_headers_flask.py -o addopts=''
```

Result: **466 passed**, no failures in the runnable subset. The new rollback regression test is in `test_web_app.py` and is NOT verified in the current environment.

The full suite is **not** validated: Flask and PyOTP are not installed in this execution environment; network DNS failure prevents installing them. These blocked Flask integration modules remain unverified: `test_web_app.py`, `test_dashboard_pages.py`, and `test_security_headers_flask.py`.

## Reproduction on a development workstation

In PowerShell (Python 3.12+ recommended by existing project documentation):

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pytest -q -o addopts=''
$env:REGEXSOC_ENV = 'development'
python run.py
```

Set `REGEXSOC_SECRET_KEY` explicitly in a production environment, and never use Flask's development server in production.

## Remaining priorities

1. Run the full integration suite in an environment with installed dependencies; fix newly surfaced failures.
2. Validate application startup and critical authentication, RBAC, and upload workflows.
3. Introduce additive Alembic migrations after inspecting the existing database schema and data-preservation requirements.
4. Continue the ingestion/normalization phase with verified CSV/JSON support.
