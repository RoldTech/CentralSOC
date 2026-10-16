# CentralSOC v1 — Professional SOC UI refresh

A restrained visual design update based on the selected **Unified Command Center** concept.

- Dark navy and charcoal canvas, gentle teal interactive accents.
- Severity retains muted red, amber and blue indicators. No decorative neon, gradient overload or invented live metrics.
- Improved table spacing, numeric risk-score alignment, filter consistency, dashboard KPI contrast and responsive chart panels.
- Existing Flask routes, RBAC, export behavior, multi-file ingestion, migrations and data handling are unchanged.
- Existing charts still require actual stored events and an appropriate date range; use All Time for historical logs.

## Updating

Back up the running CentralSOC folder and SQLite database. Copy `regexsoc/web/static/css/app.css` from this release into the matching location in your working application. Restart Flask and hard refresh the browser (`Ctrl+Shift+R`). No migration required.

To test the full standalone archive, set up a virtual environment, install requirements, configure a **copy** of your existing database and secret key, then run tests. Do not overwrite `.env`, `instance`, SQLite databases or locally uploaded evidence.

## Verification limits

The change is stylesheet-only; automated template and CSS sanity checks are performed. Full browser and production security testing must still run locally.
