# Phase 24 — Analyst triage workload

This increment adds a read-only panel on the SOC overview. It shows database-derived active (`New`, `Investigating`) alert totals, unassigned alerts, counts by status, and up to 12 assigned analyst workloads ordered by active alert count. The highest risk score is a maximum of assigned active alert risk scores, not a claim about analyst performance.

- Uses existing alert assignment column introduced in the Phase 23 migration (`c823a9d11f30`). No new database migration is required.
- Queries are aggregated in SQL; no unbounded per-alert list is materialized.
- Panel is available only to users with `view_alerts`; users without that permission never trigger the query.
- Closed/false-positive alerts are excluded. It does not calculate SLA, throughput, mean time to acknowledge, or other metrics without sufficient event timestamps.
- Database and code tests include empty data, assigned and unassigned queues, closed-exclusion, max risk, ordering, and RBAC template contract.

## Applying locally

Back up your project, `.env`, `instance/`, SQLite database and uploaded evidence first. Extract this package and merge the `regexsoc` and `tests` folders into your existing project. **Do not replace** your `.env`, `.venv`, `instance`, or SQLite data. If you have not installed Phase 23, upgrade its migration only after confirming you are pointed at your intended database. Run `python -m alembic current`, `python -m pytest -q`, then `python run.py` in a properly configured development terminal. Refresh the dashboard.

The development environment used for this package did not have Flask installed. The non-Flask suite passed, but integration, browser rendering, migration on a live user database, and production deployment remain unverified.
