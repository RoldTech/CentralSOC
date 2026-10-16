# CentralSOC: Security Log Analyzer & Threat Detection Tool

A defensive, regex-driven log analysis engine that parses Linux/SSH, Apache/Nginx, Windows-style and firewall logs into a
normalized event model, detects suspicious activity, extracts IOCs, scores risk transparently and produces analyst-ready alerts.

> **This project is intended for defensive security monitoring, log analysis, and educational purposes. It does not perform unauthorized exploitation or offensive actions.**

See [UI upgrade, verification and capability roadmap](docs/flight-recorder-upgrade.md) for the current changes and limitations.

## Latest fixes

See [Security Memory, AI diagnostics and muted SOC UI](docs/memory-ai-ui-fixes.md) for this update.

## Response and investigation upgrade

See [operations upgrade instructions](docs/operations-upgrade.md) before updating an existing database. Includes approved local snapshot runs, evidence briefs and optional AI investigation.

## Status

| Phase | Scope | State |
|---|---|---|
| 1 | Parsers, 24 detection rules, correlation, IOC extraction, risk scoring, alerts, CSV/JSON export, CLI, live monitor, sample logs, tests, rule docs | **Done** |
| 2 | SQLAlchemy persistence, SHA-256 file hashing and event hash chain, audit log, alert workflow | **Done** (confirmed working) |
| 3 | Flask app: Argon2, TOTP MFA, RBAC, CSRF, secure upload, security headers, REST API | **Done** (confirmed working) |
| 4 | SOC dashboard, search, filters, notifications, log analysis/reports/settings pages | **Done** |
| 5 | Email Security & Phishing Detection module | **Phase 1-3 done** (parsing + SPF/DKIM/DMARC + phishing indicators/scoring — see [docs/email-security.md](docs/email-security.md)) |

The web dashboard, REST API, CLI and Email Security parser (Phase 1) are all working today — see the Quick start below.

## Quick start

```bash
python3 --version   # 3.12+ required
python -m regexsoc analyze sample_logs/ssh_auth.log --year 2024
python -m regexsoc analyze sample_logs/apache_access.log --format json --severity high
python -m regexsoc extract-iocs sample_logs/ioc_sample.log --type url
python -m regexsoc report sample_logs/windows_auth.log --output report.txt
python -m regexsoc rules list
python -m regexsoc rules disable RULE-010
python -m regexsoc monitor /var/log/auth.log            # read-only follow mode
pip install -r requirements.txt && python -m pytest    # run the tests

# Phase 2: database, integrity and audit (needs SQLAlchemy)
python -m regexsoc ingest sample_logs/ssh_auth.log --year 2024 --user alice
python -m regexsoc verify                                # SHA-256 + event hash chain
python -m regexsoc alerts list --severity high
python -m regexsoc alerts set-status ALERT-XXXXXXXXXX investigating --user alice
python -m regexsoc audit

# Phase 3: web dashboard (needs SQLAlchemy, Flask, and the other requirements below)
$env:REGEXSOC_ENV = "development"                      # PowerShell; use `export` on macOS/Linux
$env:REGEXSOC_SECRET_KEY = "dev-only-not-for-production"
python -m regexsoc users create admin --role ADMIN
python run.py                                           # then open http://127.0.0.1:5000/login

# Phase 5: email parsing + SPF/DKIM/DMARC evaluation
python -m regexsoc email analyze sample_emails/phishing_password_reset.eml
python -m regexsoc email analyze sample_emails/benign_newsletter.eml --format json  # phishing verdict + indicators now included
```

## Example detection

```
$ python -m regexsoc analyze sample_logs/ssh_auth.log --year 2024 --severity high
[CRITICAL  90] RULE-002 SSH Brute Force x1 from 203.0.113.50
    why: 47 matching events from 203.0.113.50 within 300s (threshold 10).
[CRITICAL  85] RULE-004 Successful Login After Multiple Failures x1 from 203.0.113.50 (users: root)
    why: Successful login from 203.0.113.50 after 47 failures within 600s.
[HIGH      75] RULE-003 Password Spraying Indicator x1 from 198.51.100.23
    why: 198.51.100.23 touched 7 distinct username values within 600s (threshold 5).
```

## Example IOC extraction

```
$ python -m regexsoc extract-iocs sample_logs/ioc_sample.log --exclude-private
CVE        CVE-2021-44228  (x1)
DOMAIN     malicious-example.xyz  (x1)
SHA256     e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  (x1)
URL        http://malicious-example.xyz/dropper.exe  (x1)
```

Note: Python treats documentation ranges (RFC 5737) as private/reserved, so `--exclude-private` also hides the sample IPs.

## Detection rules

24 rules: authentication (001-004), network (005), web attacks (006-010, 013), reconnaissance (011-012),
IOC extraction (014-023) and known-IOC watchlist match (024). Every rule documents what it detects, why it matters, an
example log, its regex, severity, risk contribution, likely false positives and the recommended analyst action:
see [docs/detection-rules.md](docs/detection-rules.md), which is generated from the code.

## Risk scoring

Configurable, itemised and honest about its limits: see [docs/risk-scoring.md](docs/risk-scoring.md).
The score is a triage aid, **not** a probability of compromise.

## Integrity and audit

Ingested files are copied under random names, hashed with SHA-256 and their events are linked in a hash chain, so edits,
deletions and insertions are detectable. Analyst actions are written to an audit log with secrets redacted and control
characters stripped. Hashing provides **integrity verification, not confidentiality**; see [docs/integrity.md](docs/integrity.md)
and [docs/database-schema.md](docs/database-schema.md).

## Architecture

See [docs/architecture.md](docs/architecture.md) and [docs/detection-engine.md](docs/detection-engine.md).

## Security controls (current)

- Log files are only ever read as text, never executed or imported. Decoding errors are replaced, not raised.
- Input limits: 8 KiB per line, 50 MB per file (configurable), bounded query-parameter parsing.
- Patterns avoid nested quantifiers. Web payloads are decoded twice before matching.
- CSV export neutralises formula injection (`= + - @ TAB CR`).
- The monitor opens files read-only and never modifies logs. The tool never acts against external systems and only *recommends* responses.
- Stored copies get random names, are opened with exclusive-create and made read-only; display names are sanitized.
- SHA-256 file hashing plus a tamper-evident event hash chain (optional HMAC key); audit log with secret redaction and log-injection protection.
- All database access uses the ORM (parameterized queries).
- Errors are reported, never swallowed (for example a corrupt rule-state file fails loudly).

Web-application controls (auth, MFA, RBAC, CSRF, upload hardening, headers, audit log) arrive in Phases 2-3.

## Testing

`pytest` runs positive, negative and false-positive tests for parsers, rules, correlation, IOCs, scoring, export, CLI
and the streaming analyzer. The suite was mutation-checked: deliberately breaking a rule makes the relevant tests fail.

## Limitations

- Syslog timestamps have no year (use `--year`), and a Dec-to-Jan rollover is not handled.
- Only access-log fields are visible: no POST bodies or encrypted payloads. User-Agents can be spoofed.
- Logs without timestamps cannot be correlated.
- Regex detection has false positives and false negatives by nature. Tune thresholds in `regexsoc/rules/definitions.py`.
- The `/login` path is deliberately not treated as sensitive (it is normal traffic). Brute force on it should be caught through auth-failure rules once web-login events are modelled.
- The hash chain is tamper-evident, not tamper-proof (see docs/integrity.md).
- Rule enable/disable state is still a JSON file; it moves into the database with rule management in Phase 3.

## Future improvements

PostgreSQL support, threat-intel feed integration, GeoIP enrichment, Sigma rule import, more log formats (JSON, CloudTrail), ML anomaly baselines.

### Local startup checks (Phase 12)

Run `python -m regexsoc.doctor` to inspect your current `.env` and SQLite
migration revision **without creating or modifying database files**. On Windows,
`scripts/start-dev.ps1` checks the existing environment before running the app.
See `docs/phase12-local-workflow.md`. Keep your original `.env` and `instance/`
when applying updates; a freshly extracted ZIP does not include either.


## Phase 21 — Investigation workspace
See `docs/phase21-investigation-workspace.md`. Alert detail provides bounded cross-file event leads, quick navigation, and links to associated incidents with RBAC protection.


Phase 30: see `docs/phase30-email-incident-linking.md` for email-case to incident associations and migration notes.


## RBAC stabilization increment

See `docs/v1-soc-rbac.md` for new SOC roles, migration precautions, and validation instructions.
