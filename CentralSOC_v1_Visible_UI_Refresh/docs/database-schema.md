# Database Schema

SQLAlchemy 2.0 ORM, SQLite by default (`sqlite:///instance/regexsoc.db`). Set `DATABASE_URL` to use PostgreSQL later; only
portable column types and the generic `JSON` type are used. Timestamps are stored as naive UTC. All access goes through
the ORM, so queries are parameterized.

| Table | Purpose | Key columns |
|---|---|---|
| `log_files` | One row per ingested file | `sha256` (unique, of the stored copy), `stored_name` (random), `original_name` (sanitized), `uploaded_by`, `event_count` |
| `events` | Normalized events | `log_file_id`, `seq`, all normalized fields, `raw_log`, `prev_hash`, `hash` |
| `detections` | Every rule firing | `rule_id`, `category`, `severity`, `risk_score`, `source_ip`, `reason`, `evidence` |
| `alerts` | Detections at or above the alert threshold, plus workflow | `alert_id` (unique), `status`, `updated_by`, `updated_at`, `note` |
| `iocs` | Extracted indicators | `ioc_type`, `value`, `event_id`, `timestamp`, `context` |
| `audit_log` | Application audit trail | `timestamp`, `username`, `action`, `ip_address`, `result`, `resource`, `detail` |

Constraints: `UNIQUE(log_file_id, seq)` on events; `CHECK(status IN ('New','Investigating','Resolved','False Positive'))` on
alerts; foreign keys cascade on delete (SQLite foreign keys are switched on explicitly).

Users, roles and login-attempt tables arrive with the web app in Phase 3.

## Design notes

- **Idempotent ingest.** `log_files.sha256` is unique. Re-ingesting identical content returns the existing record.
- **Scoped alert IDs.** `alert_id = "ALERT-" + first 10 hex of SHA-256(file hash | analyzer alert id)`, so IDs are stable but unique per file content.
- **Public identifiers.** The web app will expose integer primary keys behind authorization checks (protecting against IDOR), never file paths.
