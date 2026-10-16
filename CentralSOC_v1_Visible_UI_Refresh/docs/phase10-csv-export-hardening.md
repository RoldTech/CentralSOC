# Phase 10 — CSV export security increment

## Scope

CSV export is consumed by spreadsheet applications. A formula-like string can be dangerous when it appears in exported records or in caller-provided column names. Prior protection skipped literal spaces only and did not sanitize header cells.

## Changes

- `regexsoc/services/export.py`: inspect all leading Unicode whitespace before determining whether a string begins with a formula-trigger character, and escape user-supplied CSV header names using the same sanitizer as data cells. Original dictionary field names are still used to look up each row's values.
- `tests/test_export.py`: add four whitespace formula regression cases and a header-name regression test.

## Validation

- `python -m pytest -q tests/test_export.py`: 20 tests passed.
- `python -m pytest -q --ignore=tests/test_web_app.py --ignore=tests/test_security_headers_flask.py --ignore=tests/test_incident_web_contract.py --ignore=tests/test_dashboard_pages.py`: passed (runnable subset).
- `python -m compileall -q regexsoc tests`: passed.

## Limitations

Flask is not installed in this runner; four Flask-dependent test modules could not be run. Full browser and authorization integration checks remain required. CSV risk also depends on the spreadsheet application and how files are subsequently imported or transformed; this is a defense-in-depth measure, not a complete guarantee. No production deployment or database changes were performed.
