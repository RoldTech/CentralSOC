# CentralSOC response and investigation foundation

## Included
- Persistent response runs: request, approve/reject, execute once. The supported action is a local snapshot of up to 100 linked alerts' metadata, captured at execution time. This is not a copy of raw evidence or a network containment connector.
- Managers and administrators approve/reject. Incident-managing roles request and execute. A manager/admin may approve their own request because this action only records local metadata; this is not four-eyes separation.
- Conditional database transitions prevent repeat execution. Run changes and audit entries commit together. Failures roll back; no external action is involved.
- Local investigation briefs retrieve up to 25 source events and five matching prior verdicts. Each run persists its input bundle and result. Memory match means same rule, IP or username; it is not semantic similarity or a verdict recommendation.
- Optional AI advisory investigation using the OpenAI Responses API. Disabled by default. Per-request UI consent, 25-second socket timeout, bounded input/output, no automatic retries, no action tools, and no automatic verdict updates. API response storage is disabled with store=false; this is not a guarantee of zero provider retention.
- AI receives only rule ID, severity/risk/status, timestamps, event types, reference IDs and prior verdict labels. Raw logs, IP/account values, analyst notes and verdict reasons are excluded. Model references and conclusions are unverified and require analyst review. This limited metadata cannot support a full forensic conclusion.
- Investigation request limit: 10/minute per user per server process. Production multi-worker deployments need a shared limiter and asynchronous job queue.
- Fixed malformed incident-title markup and the split Regex/SOC login brand.

## Validation
614 Python/Flask tests passed, including a complete HTTP workflow: login → upload → alert verdict → Security Memory → investigation → incident link → snapshot request → approval → execution. Includes permissions, missing CSRF, duplicate execution, rejected runs, provider failure, output escaping, and migration/schema checks.
The provider contract uses mocks; no live AI request or API charge was made. Browser testing remains unverified because the runtime browser download failed. The optional browser script is supplied but has not been executed here.

## Upgrade procedure
Back up the database, uploads, application and environment; stop the old application.
Install requirements in your virtual environment. This release adds two tables.
- Existing Alembic-tracked database: configure DATABASE_URL for that database and run `python -m alembic upgrade head` BEFORE starting the new app.
- Untracked database from the previous release: using the PREVIOUS release's environment/code, run `python -m regexsoc.db.migration_baseline` to verify and stamp its matching schema first. Then switch to this code and run `python -m alembic upgrade head`. If verification refuses, do not force-stamp; inspect the mismatch.
- New installation: run `python -m alembic upgrade head`, create your admin using the existing README, then start the app.
Run `python -m pytest -o addopts='' -q`, then `python run.py` using your existing configuration.
Do not run migrations against the only copy of your production database. Rollback: stop the app, restore the pre-upgrade database and prior code together. Downgrading removes the new run records.

## Use it
Open an alert → Investigation assistant → Build local evidence brief.
Open an incident → Response orchestration → Request snapshot. Sign in as SOC_MANAGER/ADMIN to approve; then an incident-managing user can execute it.
AI setup: set CENTRALSOC_AI_ENABLED=1, CENTRALSOC_AI_MODEL to a Responses-compatible model available to your API project, and OPENAI_API_KEY in the server environment. Restart the app. Review the per-request metadata disclosure before clicking Request AI investigation. Never commit credentials.

## Optional real browser validation
In an isolated development environment:
```
python -m pip install playwright
python -m playwright install chromium
python scripts/browser_workflow.py
```
Uses a temporary database, generated test credentials and sample logs; does not use your live database or enable AI. Writes desktop/mobile triage screenshots to test-results. Review layout and screenshots manually.

## Remaining scope
This release is a foundation, not a complete autonomous immune system. External EDR/firewall/identity connectors, distributed workers, timeout/retry recovery, stronger separation of duties, rollback of external actions, continuous telemetry collectors, immutable external evidence storage, and live AI/browser/staging validation remain outstanding.

API contract reference: https://developers.openai.com/api/reference/resources/responses/methods/create
