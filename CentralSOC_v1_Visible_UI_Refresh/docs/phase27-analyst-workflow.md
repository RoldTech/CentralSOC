# Phase 27 — Alert handoff, verdicts, and email workflow

## Delivered
- Alert queue risk scores centered in a fixed-size, tabular numeric column.
- Filtered alert CSV export (`GET /alerts/export.csv`), server-side `view_alerts` permission, validated existing queue filters, at most 1,000 rows, OWASP-style spreadsheet-formula escaping, `no-store`, and export audit log. Export contains sensitive account/IP/analyst findings: share only via approved internal channels.
- Analyst alert outcome (`TRUE_POSITIVE`, `FALSE_POSITIVE`, `INCONCLUSIVE`) with mandatory explanation, actor and timestamp and an audit record. Alerts already imply a detection fired; true negatives and false negatives require a distinct, independently verified dataset review, **not** an alert status.
- A readable alert activity presentation, improved note textarea, and unified layout for email analysis, including an explicit note distinguishing claimed header results from independent checks. Email analysis remains transient and does not execute HTML or attachments.

## Migration and deployment
1. Back up `.env`, `instance/`, your actual SQLite DB and uploaded evidence **before** merging updated code and migrations.
2. Confirm `DATABASE_URL` points to your existing database (`python -m alembic current -v`). An empty revision output may mean the wrong database; stop and check before upgrading.
3. In your already activated VS Code environment, run `python -m alembic upgrade head` after verifying your backup; expected revision `e29a6c7d41b0`.
4. Run `python -m pytest -q` with Flask installed and test logging in, alert export, save/reload verdict, and note timeline; do not use a new empty extraction folder as your working DB unless intended.
5. Restart `python run.py` in development mode and hard-refresh browser CSS.

## Validation in build workspace
- Targeted database/service and migration tests: passed.
- Jinja parsing and Python compilation: passed.
- Non-Flask regression subset: passed. Flask browser tests blocked because Flask is not installed in this workspace.
- PostgreSQL concurrency and browser-level tests remain outstanding.

## Known limitations
- CSV is a bounded handoff snapshot, not a permanent investigation package; it excludes raw evidence/attachments and is not automatically encrypted. Only authorized roles can fetch it; deployment access controls are still necessary.
- Analyst assessment is not a verified forensic conclusion. No automatic TP/TN/FP/FN performance metrics are inferred.
- Email security does not yet persist cases, verify all DNS records independently, or scan attachments/URLs in a sandbox. Its verdict is evidence-based but not proof of maliciousness.
