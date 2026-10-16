# Architecture

```
raw line -> parsers/ -> Event -> +- detectors/regex_detector  (per-event rules)   -+
                                 +- detectors/correlation     (sliding windows)    +-> Detection
                                 +- detectors/ioc             (IOC extraction)    -+       |
                                                                                            v
                                            services/risk (scores, bands, per-IP profiles) -> services/alerts
```

| Package | Responsibility |
|---|---|
| `regexsoc/models.py` | Normalized `Event`, `Severity`, `EventType` |
| `regexsoc/parsers/` | syslog/SSH/sudo/firewall, Apache/Nginx, Windows-style, generic fallback |
| `regexsoc/rules/` | Rule catalogue (data only), enable/disable store, docs generator |
| `regexsoc/detectors/` | Event rules, correlation rules, IOC extraction |
| `regexsoc/services/` | Analyzer pipeline, risk scoring, alerts, stats, export, report, live monitor |
| `regexsoc/cli/` | argparse CLI |
| `regexsoc/db/` | SQLAlchemy models, sessions, ingest / verify / alert-workflow / audit services (imported lazily) |
| `regexsoc/security/` | SHA-256 + hash chain, audit sanitizing, filename sanitizing |
| *(Phase 3+)* `web/`, `api/` | Flask app, REST API, authentication |

## Design decisions

- **Engine first, UI second.** The engine has no Flask dependency, so the CLI, API and dashboard share one tested core.
- **Rules are data.** A `Rule` holds patterns, severity, score, response and documentation. `docs/detection-rules.md` is generated from that data.
- **Regex selects, code correlates.** Windowed logic (brute force, spraying, scans) uses a regex to pick candidate events and then counts per source IP over a sliding time window. This is more accurate than any single regex.
- **Decode before matching.** Web targets are URL-decoded twice, so `%252e%252e%252f` is caught.
- **Bounded input.** Lines are truncated to 8 KiB and files are size-limited, which limits regex cost (ReDoS) on hostile input. Patterns avoid nested quantifiers.
- **All timestamps are UTC.** Syslog lacks a year, so `--year` is supplied (default: current year).

## Data model (Phase 2, implemented)

See [database-schema.md](database-schema.md) and [integrity.md](integrity.md).

## Planned API (Phase 3)

`GET /api/events[/<id>]`, `GET /api/alerts[/<id>]`, `PATCH /api/alerts/<id>`, `POST /api/logs/upload`, `GET /api/iocs`,
`GET /api/statistics`, `GET|POST /api/rules`, `PATCH /api/rules/<id>`. Every route needs authentication plus a role check
(ADMIN / ANALYST / VIEWER), validated input, CSRF protection for browser sessions and proper status codes.

## Planned security model (Phase 3)

Argon2 password hashing, TOTP MFA, server-side session timeout, lockout plus rate limiting, RBAC decorators on every
route, CSRF tokens, secure/HttpOnly/SameSite cookies, CSP and other security headers, randomized upload names stored
outside the web root, extension + magic-byte + size validation, and an audit log.
