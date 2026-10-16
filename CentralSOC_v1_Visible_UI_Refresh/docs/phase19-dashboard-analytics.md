# Phase 19 — Database-backed dashboard analytics

## Changes

- New 7-day / 30-day UTC analytics query, restricted to those two windows.
- Events vs alerts timeline; severity ring; detection categories; authentication outcomes.
- Dependency-free, responsive Canvas renderer in `regexsoc/web/static/js/soc_charts.js`.
- No fabricated counts; blank data produces an explicit empty-state message.
- Existing RBAC-protected overview route and incident permissions remain intact.
- All values in the charts come from persisted database records. The timestamps are event-time, not ingestion-time; events without timestamps are excluded from charts.
- `func.date()` groups data by stored timestamps in SQLite and is intended to support PostgreSQL; production PostgreSQL behavior remains unverified.

## Deployment on Windows

Back up the current project (including `.env` and `instance/`). Extract this ZIP and copy `regexsoc/` over your current project files, keeping `.env`, `.venv`, `instance/` and any uploaded data. No migration is needed. In the existing activated environment run:

```powershell
python -m pytest -q
$env:REGEXSOC_ENV = 'development'
python run.py
```

Hard refresh the overview page using Ctrl+Shift+R. Select **7 days** or **30 days**. To populate charts, ingest a synthetic log with timestamps inside the selected window. Do not expect a historical 2024 sample log to show in October 2026 windows.

## Verification

- `python -m pytest -q tests/test_dashboard_analytics_phase19.py` — 2 passed.
- All tests apart from three Flask-dependent modules completed with passing status in this sandbox. Flask is not installed here; full web integration remains unverified.
- `node --check regexsoc/web/static/js/soc_charts.js` — passed.
- `python -m compileall -q regexsoc` — passed.

## Known limitations

- Charts are server-rendered on page load, not live-streaming or automatically refreshed.
- Current time ranges are daily UTC windows; not hour-level or true historical ingestion throughput.
- An index on Alert.timestamp / Detection.timestamp may become important at significant data volumes; benchmark before claiming scale.
- Test in a real browser and verify keyboard accessibility and canvas screen-reader alternatives before production use.
