# Phase 30 — Email Case ↔ Incident Associations

Adds an explicit many-to-many association, `email_case_incidents`, with a unique constraint, references to existing case and incident records, analyst attribution, and audit events. No raw email content, URLs, or attachments are stored by this increment.

## Workflow

1. Open an existing saved Email Security case.
2. An authorized incident manager may supply the numeric ID of an existing incident and link it.
3. The email case lists linked incidents, and incident detail lists linked email cases for roles allowed to use email analysis.
4. The link is idempotent: submitting the same association again creates no extra link or audit entry.

## Security and limits

- POST route requires `manage_incidents`; request goes through the application's CSRF middleware.
- Case details remain behind the existing `upload_logs` permission. Incident pages only expose email-case links to users with that permission.
- Invalid IDs are rejected, link changes participate in the request transaction, and only metadata is retained.
- This is association and navigation only; no automatic incident creation, exported handoff package, raw email custody, or independent SPF/DKIM/DMARC verification.
- Existing EmailCase status mutation still uses the pre-existing `upload_logs` permission; finer-grained email-case RBAC remains future work.

## Upgrade

Back up the actual SQLite database and preserve local `.env`, `.venv`, `instance`, and uploaded logs. Confirm `DATABASE_URL` refers to that same existing database, then run `python -m alembic current -v`, `python -m alembic upgrade head`, `python -m pytest -q`. New revision: `a91d4b67e302`. Never replace an existing database with this archive.

## Validation

Tested the new link service for audit-once, deduplication, reverse lookup and missing IDs. Validated all Jinja templates, Python compilation, and a full fresh SQLite Alembic upgrade. Flask/browser routes require verification on the user's machine.
