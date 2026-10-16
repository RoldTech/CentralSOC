# Phase 26 — Acknowledgement dashboard

This incremental update exposes the existing Phase 25 first-acknowledgement metrics on the Overview page for accounts with `view_alerts` permission.

## Changes
- `regexsoc/web/routes/dashboard.py`: permission-gated metrics query.
- `regexsoc/web/templates/dashboard/overview.html`: acknowledged count, pending count, mean time to acknowledge (minutes), and timing sample count.
- `tests/test_phase26_ack_dashboard.py`: metric correctness, empty-state, and permission-gated template regression checks.

## Metric definitions and limitations
- **Pending**: alerts with no first acknowledgement and status New or Investigating.
- **Acknowledged**: alerts with non-null first acknowledgement timestamp, regardless of current status.
- **MTTA**: arithmetic mean of nonnegative durations from original alert timestamp to first acknowledgement. Cases with missing or reversed timestamps are excluded.
- **Sample size**: number of valid acknowledgement intervals contributing to MTTA.
- All metrics are **all-time**, not scoped to the separate security telemetry 7/30-day time selector. They are not SLAs, measures of resolution, or indicators of analyst performance.
- Existing historic records without acknowledgement timestamps are not backfilled.

## Validation
- Targeted: `python -m pytest -q tests/test_phase26_ack_dashboard.py tests/test_phase25_acknowledgement.py` — 7 passed.
- Non-Flask subset: passed with `--ignore=tests/test_security_headers_flask.py --ignore=tests/test_web_app.py --ignore=tests/test_dashboard_pages.py`. Exact test count can be obtained by running without quiet mode.
- `python -m compileall -q regexsoc` — passed.
- Overview Jinja2 template parsing — passed.
- Full Flask tests were not runnable in this container because Flask is unavailable. Run `python -m pytest -q` in the user's configured Windows environment.

## Upgrade
No new migration in Phase 26. Phase 25 Alembic revision `d40f1b9267ac` must already be applied. Back up local files and database before merging; never overwrite `.env`, `.venv`, `instance`, or uploaded evidence. Run `python -m alembic current` and `python -m pytest -q` before restarting locally.
