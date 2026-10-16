# Phase 4 — Detection reliability and in-batch alert deduplication

## Changes
- `regexsoc/detectors/correlation.py`: a success-after-failures detection does not count failures belonging to a different known username on the same source IP. If an identity is missing, the existing IP-only fallback remains and should be treated as lower-confidence evidence in future work.
- `regexsoc/services/alerts.py`: within a single analysis batch, alerts that share the same deterministic alert ID merge distinct event IDs and bounded evidence (20 lines), keeping the highest-scored match. Different rules/accounts remain separate. This is **not** persisted, cross-ingestion alert suppression or full time-window correlation.
- `tests/test_alert_dedup.py`, `tests/test_correlation.py`: regression tests for false-positive correlation and same-ID merging.

## Validation
- `pytest -q tests/test_alert_dedup.py tests/test_correlation.py`: 19 passed.
- `pytest -q --ignore=tests/test_web_app.py --ignore=tests/test_dashboard_pages.py --ignore=tests/test_security_headers_flask.py`: 483 passed.
- Flask-dependent modules remain excluded because Flask is unavailable in this environment. Do not represent this as a full integration pass.

## Limitations and next work
- Existing deterministic alert IDs incorporate the first event ID and are not a stable cross-batch incident fingerprint; database-level deduplication is unimplemented.
- Correlation still falls back to IP-only when account identity is missing; analysts must interpret such evidence cautiously.
- Run Flask startup/integration tests and migration checks in a properly provisioned virtual environment before deployment.
- Next: define durable correlation fingerprints, safe alert upserts, analyst assignment and audit-trailed lifecycle management.
