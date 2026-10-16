> Historical UI release notes. For the current backend changes and migration instructions, see [operations-upgrade.md](operations-upgrade.md).

# CentralSOC UI and Security Memory upgrade

## Verified changes
- Navy/cyan shared interface aligned with the supplied triage reference.
- Four triage counters computed across the entire filtered result set: New, Assigned to Me, risk >=80, and no analyst verdict.
- Investigation action per row; existing filtering, export, roles and CSRF retained.
- Security Memory at /security-memory searches stored analyst verdicts by detection, IP or username and links to the original evidence. It shows the latest verdict per alert, not a separate immutable knowledge store.
- Remaining RegexSOC titles in web templates replaced with CentralSOC. Python package names, environment variables and database identifiers remain compatible.
- Fixed a timezone-dependent test: compare naive UTC with naive UTC, with a bounded one-hour expectation.

## Validation
Original ZIP integrity passed. Original test run: 605 passed and 1 failed (timezone-dependent test). Updated full suite: 608 passed, including memory authentication, verdict retrieval, search and triage rendering checks. These are Python/Flask integration tests, not complete browser or production validation. No claim of zero possible errors.

## Beyond SIEM: actual state and next implementation gates
1. Flight recorder: existing raw logs, file hashes, event hash chains, provenance and audit history form a foundation. Add continuous collectors, retention policy, external immutable checkpoints and replay validation before describing it as a complete forensic recorder.
2. Security memory: this release provides searchable analyst decisions. Next add versioned case lessons, entity relationships, outcome evidence, controlled corrections and provenance-aware retrieval. Never automatically suppress an alert because a similar past alert was benign.
3. Response orchestration: existing incident playbooks are manual. Real orchestration needs persistent action/run records, approved connectors, scoped credentials, approval policies, idempotency, timeouts, retries, rollback and execution audit. No endpoint isolation, firewall blocking or account disabling is implemented by this UI release.
4. AI investigation: not implemented. Add a configured model provider, bounded evidence retrieval, citations to actual events, explicit uncertainty, prompt-injection isolation and human-reviewed conclusions. Separate model suggestions from executable response actions.
5. End-to-end testing: add browser workflows for login/MFA, upload, triage, verdict, memory retrieval and incident playbooks; then connector simulations and staging recovery tests. Existing Flask tests cover substantial workflows but do not prove real connector behavior or deployment readiness.

## Updating an existing installation
Back up the application, database, uploads and environment configuration first. Extract into a separate directory; preserve existing environment values and point it at the intended database/upload locations. This update adds no database columns or migrations. Install requirements in a virtual environment and run `python -m pytest -o addopts='' -q`. Start using the existing documented run.py procedure. Hard-refresh the browser; the CSS version changed to soc-flight-1. Keep the previous application folder available for rollback. This artifact has not been deployed to your machine or public hosting.

Browser visual verification could not be completed: the Playwright browser download returned a truncated archive in this environment. Rendered Flask HTML was checked, but screenshot and browser end-to-end checks remain outstanding.
