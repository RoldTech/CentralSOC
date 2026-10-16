# CentralSOC Phases 13–18: Incremental delivery and evidence

This release builds on Phase 12. **It does not claim enterprise production readiness.**

## Phase 13 — SOC workflow verification (implemented, database-level)
`tests/test_soc_workflow_phase13.py` exercises synthetic SSH log ingestion, event storage, alert detection, incident creation, alert linkage, analyst note, manual playbook completion, and verification of the event integrity chain. Flask browser end-to-end tests are **not verified** in this execution environment.

## Phase 14 — Analyst-facing UI (implemented)
- Fix account menu inadvertently being displayed when it has the HTML `hidden` attribute.
- Render existing incident audit detail JSON as readable, safely Jinja-escaped text without changing the underlying audit records. Unknown or malformed detail is intentionally not rendered verbatim.
- Test formatting logic.

## Phase 15 — Detection consistency (additional regression coverage)
- Add coverage guarding unrelated-account successful login interpretation.
- Existing correlation remains batch-local; cross-ingestion deduplication and suppression are **not implemented**.

## Phase 16 — Offline threat intelligence (optional foundation)
- Add `regexsoc.services.threat_feed.load_feed(path)` for analyst-reviewed local JSON feeds, schema/size/count validation, source attribution, indicator normalization and expiration. Feed records require keys `type`, `value`, `source`, and `expires_at` (ISO 8601 offset-aware timestamp). Types: `ipv4`, `ipv6`, and `domain`.
- `Analyzer.from_feed_file(path)` builds the existing watchlist detection logic from unexpired entries. This is an opt-in code API, not a dashboard feed-import UI. Feed files are not fetched over the network. No automated blocking or containment.
- Enrichment provenance is appended to an applicable watchlist finding's reason.

Example (only in a trusted local Python environment):

```python
from regexsoc.services.analyzer import Analyzer
analyzer = Analyzer.from_feed_file('reviewed_iocs.json')
result = analyzer.analyze_file('sample_logs/ssh_auth.log')
```

## Phase 17 — Incident reporting (implemented, bounded)
- `GET /incidents/export.csv` provides at most 1,000 recent cases, requires `view_incidents`, escapes CSV formulas using the existing safe serializer, and sends `Cache-Control: no-store`.
- Includes case metadata, no evidence bodies or raw log content. Advanced KPI reports and scheduled reporting remain future work.

## Phase 18 — Security and deployment verification (partial)
- Added tests for bad/expired threat feed records, CSV injection, and synthetic ingestion.
- Ran local `compileall` and the available non-Flask test subset. **509 tests passed** on the available subset; Flask-dependent test modules were excluded because Flask and PyOTP are not installed in this execution environment.
- Not verified: full Flask browser tests, PostgreSQL compatibility, production WSGI deployment, backup/restore, representative performance load, multi-tenant isolation, external threat intelligence, and complete threat-model remediation.

## Commands used

```powershell
python -m pytest -q --ignore=tests/test_web_app.py --ignore=tests/test_dashboard_pages.py --ignore=tests/test_security_headers_flask.py --ignore=tests/test_csrf_middleware.py --ignore=tests/test_dashboard_incident_metrics.py --ignore=tests/test_incident_web_contract.py
python -m compileall -q regexsoc tests
```

The complete suite on an installed Windows environment remains required:

```powershell
python -m pip install -r requirements.txt
python -m pytest -q
python -m regexsoc.doctor
```

## Safe update procedure

1. **Stop Flask.** Back up your working project folder, `.env`, `instance` database and uploads before copying source files.
2. Extract the ZIP. Its actual project root is the inner `CentralSOC_Phase18_Development` directory containing `run.py` and `regexsoc`.
3. Merge updated `regexsoc/`, `tests/`, and `docs/` into your **existing working project**. Do not replace `.env`, `.venv`, `instance/`, local database files, uploads, or custom secrets.
4. Use your existing virtual environment and stable `REGEXSOC_SECRET_KEY`. Restart with `REGEXSOC_ENV=development` only for localhost testing.
5. No migration was added in this release. Verify your application and run the complete pytest suite.

## Existing limitations and risks

- Local SQLite is intended for development. Do not expose the Flask development server to the internet.
- Alert suppression is not yet durable across multiple uploads.
- Optional threat feed trust/provenance still requires analyst review. Matching a feed entry does not prove maliciousness.
- Audit records are not cryptographically tamper-proof solely because the application restricts edits.
- The new report export is subject to the existing RBAC framework, whose full integration tests still must be executed.
