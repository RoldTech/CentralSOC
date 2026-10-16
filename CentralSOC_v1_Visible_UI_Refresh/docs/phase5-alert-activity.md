# Phase 5 increment: persistent analyst activity

## Scope
- Existing alert statuses and SQLAlchemy schema are preserved. No destructive migration.
- Analyst notes are appended as `ALERT_NOTE_ADDED` records to the existing audit table; the alert's `note` field remains the latest-note compatibility field.
- Status updates and optional notes produce distinct audit actions. Analyst activity is visible on alert detail pages, newest first (100 entries maximum).
- A dedicated permission-protected, CSRF-protected note form was added to the alert detail page.
- Notes are capped at 1000 characters, scrubbed of control characters, and redacted by existing audit sanitation.
- All changes participate in the request transaction; rollback removes both note and audit entry.

## Limitations / follow-ups
- The audit table is not write-once or tamper-proof, and is a provisional activity history rather than a full investigations model.
- Full Flask page and authentication tests remain blocked in the present environment because Flask is not installed; they need local verification.
- Assignment, incident association, status transition policy, and durable evidence referencing remain future increments requiring new migrations.
- Do not use this as production evidence without additional controls for log retention and tamper-resistance.

## Validation
- `pytest -q tests/test_alert_activity.py` passed (4 tests).
- Non-Flask test subset passed after excluding Flask-dependent test modules.
