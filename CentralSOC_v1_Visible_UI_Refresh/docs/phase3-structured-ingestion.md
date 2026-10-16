# Phase 3 increment — Structured security event ingestion

## Implemented

- Web upload validation now permits `.csv`, `.json`, and `.jsonl` in addition to `.log`/`.txt`.
- Structured records normalize into the existing `Event` model and pass through the original detection, correlation, IOC, risk, and persistence paths.
- JSON accepts an array of event objects, one event object, or an object with an `events` array. JSONL accepts one object per nonempty line. CSV requires a header row.
- Supported aliases: timestamp/@timestamp/event_time/time; source_ip/src_ip/src; destination_ip/dest_ip/dst_ip/dst; username/user; auth_status/outcome; event_type/event_category; host/hostname; ports and HTTP fields.
- ISO timestamps are converted to UTC. Missing timestamps remain missing. Unrecognized event type values and invalid timestamps, ports, IPs, HTTP status, and authentication status yield explicit rejection, not invented values.
- Strict UTF-8 decoding, duplicate JSON key rejection, CSV header/column checks, 100,000 record bound, 128 field bound and per-record length checks.
- Original `.log`/`.txt` parser behavior is preserved. Existing storage, hash chain and duplicate-file handling are reused.
- Malformed structured files produce `UploadRejected` via the web upload path, resulting in HTTP 400; no success is silently reported.

## Known limitations / next steps

- Ingestion is still all-or-nothing; per-record accepted/rejected counters, streaming JSON and batch database writes remain future work. The existing size limit bounds uploads, but large JSON arrays can use substantial memory.
- Unknown fields remain in serialized raw evidence and are not indexed. Uploaded data must be synthetic or sanitized; redaction and retention policy work is not complete.
- CSV handles each row as one event; arbitrary vendor schemas need adapters.
- HTTP integration tests, full Flask startup, and PostgreSQL have not been verified in the current environment because dependencies are unavailable.
- Schema migrations were not required for this increment; no database file was reset.

## Validation

`python -m pytest -q tests/test_structured_ingestion.py tests/test_upload_validation.py`

`python -m pytest -q --ignore=tests/test_web_app.py --ignore=tests/test_dashboard_pages.py --ignore=tests/test_security_headers_flask.py`

Both passed in the current environment. The three excluded modules need a Flask-equipped environment. Never interpret this as a production readiness claim.
