# CentralSOC v1.0 — Batch Log Upload

The dashboard Log Analysis form accepts 1–8 files in one multipart POST. Supported file types are `.log`, `.txt`, `.csv`, `.json`, and `.jsonl`, subject to the existing validation and per-file size setting (`REGEXSOC_MAX_INPUT_BYTES`). A request-wide size limit is enforced by Flask and capped at approximately 100 MiB for default settings. This is not a queue/background worker; processing is synchronous.

Each file goes through `handle_upload` and the existing ingestion pipeline. The batch page lists successful, duplicate, and rejected files separately and links to persisted log-analysis results. Rejected validation does not stop the other files; an unexpected application/database failure can still abort the request and roll back the database transaction. Persisted evidence files are not automatically removed if a later unexpected database exception happens; the existing retention/cleanup mechanism should be reviewed before production use.

A single uploaded file still redirects to its existing result page. The REST `/api/logs/upload` endpoint is unchanged and still accepts one file per request.

Security: session authentication, `upload_logs` server-side permission, and CSRF checks are still required. Batch count is capped at 8 and the request body is bounded. Existing content and file extension validation remains enabled. This does not bypass upload validation or allow execution of uploaded files.

## Verification

- Available non-Flask regression subset: 561 passed.
- 31 Jinja templates parsed.
- Python compilation successful.
- Flask route integration tests were added to `tests/test_dashboard_pages.py` but were **not executed in this environment** because Flask is not installed here. Run `python -m pytest -q` on your VS Code environment before using the new feature.

## Installation

Back up the existing project, especially `.env`, `.venv`, `instance/`, uploaded evidence and SQLite data. Merge the changed `regexsoc/`, `tests/`, and `docs/` folders into your existing CentralSOC source. No database schema migration is necessary. Restart Flask and hard-refresh the browser. In **Log Analysis**, use the file chooser to select multiple files (Ctrl-click / Shift-click), then choose **Analyze selected files**.
