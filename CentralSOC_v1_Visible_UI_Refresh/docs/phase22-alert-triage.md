# Phase 22 — Alert triage queue

## Changes

- Validated filter parameters with bounds and allowlisted enumerations in `regexsoc/db/alert_queue.py`.
- Added exact-match username filtering to the Alerts page.
- Added highest risk, newest, and oldest sorting, with stable ID tie-breakers.
- Kept 25-per-page server-side pagination, time-window selection, existing RBAC and alert detail links.
- Added focused regression tests for invalid filters, cutoff behavior, account isolation, status and IP combinations.

No database schema change. No alert assignment or cross-ingestion correlation is claimed; those require separate design and migrations.

## Validation

`PYTHONPATH=. python -m pytest -q tests/test_alert_queue_phase22.py` — 2 passed.

Broad non-Flask regression subset — completed without errors. Flask-dependent tests were excluded because Flask is not installed in this execution environment; run `python -m pytest -q` in the Windows project virtual environment.

Python compile and archive integrity are checked separately. No live browser test performed here.

## Upgrade

Back up your project and preserve `.env`, `.venv`, `instance`, SQLite DB, uploads and all user-owned data. Merge the updated code into your working project, run the entire test suite, then restart Flask. The new queue requires no migration.
