# CentralSOC v1.0 dashboard — All Time analytics

The Security Telemetry header now provides **7 days**, **30 days**, and **All Time**. All Time uses persisted event and alert timestamps, including historical years. Unlike daily 7/30-day charts, the All Time event/alert timeline groups data by calendar month in UTC. Other charts aggregate all timestamped records, without rewriting old timestamps or inventing values.

The view is intentionally read-only, requires no schema migration and uses SQLAlchemy ORM aggregation (compatible in approach with SQLite/PostgreSQL, though PostgreSQL verification remains pending). With a completely empty database the chart shows a zero-data state. The labels span the earliest to latest dated Event/Alert; Detection category counts still cover the full available history.

Test locally: `python -m pytest -q tests/test_dashboard_analytics_phase19.py tests/test_dashboard_all_time.py`; then full `python -m pytest -q` in your VS Code environment. Restart Flask and click **All Time** under Security telemetry. The URL parameter is `/?days=all`.

Preserve `.env`, `instance/`, the database, and uploaded evidence when merging. This change alters only dashboard queries, route window selection, the template, chart labels, and associated tests.
