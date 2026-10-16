# Phase 9 — SOC dashboard operations

## Changes
- Added read-only database-backed incident and detection aggregation functions in `regexsoc/db/dashboard_queries.py`.
- Updated `/` overview route to pass incident metrics **only** if the signed-in role has `view_incidents`. Detection metrics are derived from persisted detection records.
- Added total/active incident cards, counts by state and five most recently updated cases, linking to their detail pages.
- Added real detection-match and unique-rule counts, with zero values when the database is empty.
- Added regression coverage for empty results, incident totals, and template/route permission gating.

## Validation in this environment
- `pytest -q tests/test_dashboard_incident_metrics.py`: passed (3 tests).
- `pytest -q --ignore=tests/test_app_factory.py --ignore=tests/test_routes.py --ignore=tests/test_csrf_middleware.py --ignore=tests/test_security_headers_flask.py --ignore=tests/test_web_app.py --ignore=tests/test_dashboard_pages.py`: passed (runnable subset).
- Flask is not installed, so the excluded Flask-dependent modules and actual browser routing are **not verified**. The production application must be tested in an environment where `pip install -r requirements.txt` succeeds.

## Limitations
- Incident and detection widgets show all-time totals; other overview widgets retain existing semantics.
- No ingestion-health or async-processing health metrics are available yet.
- This does not constitute deployment or security sign-off.
