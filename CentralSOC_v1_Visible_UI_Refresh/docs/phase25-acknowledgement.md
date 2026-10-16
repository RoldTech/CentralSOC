# Phase 25 — First alert acknowledgement

- Adds nullable `alerts.acknowledged_at` and `alerts.acknowledged_by` using Alembic `d40f1b9267ac`. Existing alerts remain unacknowledged; timestamps are not invented.
- An authorized analyst can acknowledge an alert from alert detail. CSRF and `update_alert_status` permission protect the POST request. Acknowledgement is independent of alert status and assignment. Only the first successful acknowledgement is recorded.
- The audit event is written in the same database transaction; replay attempts do not create duplicate records.
- The query helper `acknowledgement_metrics` reports pending and acknowledged counts and mean time to first acknowledgement only for rows with valid event timestamps. Invalid or absent timestamps are excluded. This metric is not yet a dashboard widget, and it is not an SLA metric.
- Deploy: back up the existing SQLite database, merge the cumulative archive, verify `DATABASE_URL`, run `python -m alembic current`, `python -m alembic upgrade head`, and `python -m pytest -q` on your local installation. Never overwrite `.env`, `instance`, or uploads.
- Outstanding: Flask/browser integration, concurrent-acknowledgement tests under PostgreSQL, authenticated API behavior, workload metric UI, and production readiness.
