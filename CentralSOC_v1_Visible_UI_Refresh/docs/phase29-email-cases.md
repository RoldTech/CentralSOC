# Phase 29 — Email investigation cases

## Scope

Every successful manual `.eml`/raw-email analysis now saves a metadata-only case with a SHA-256 fingerprint of the submitted bytes, bounded sender and subject, the existing heuristic classification and score, creation time and analyst identity. Cases are listed at `/email-security/cases`; analysts may update status (Open, Investigating, Escalated, Closed) with a required note. Status updates and case creation are captured in the existing audit log. CSRF and the existing `upload_logs` permission protect routes.

**Deliberate exclusions:** no raw email, body, HTML, attachment, URLs or full extracted IOCs are persisted; this is *not* an evidence vault or forensic chain of custody. Redacted/truncated audit notes are not an authoritative evidence store. No automatic IOC enrichment, malware scanning or external link retrieval occurs. No direct case-to-incident relationships yet. The sender/subject can contain sensitive personal information and require an operational retention policy.

## Update from Phase 28

Back up the current database and `.env` before merging. Keep `.env`, `.venv`, `instance`, local SQLite data and uploads unchanged. Merge the new source, templates and `migrations` directory and confirm `DATABASE_URL` points to your working database. Run:

```powershell
python -m alembic current -v
python -m alembic upgrade head
python -m pytest -q
python run.py
```

The new Alembic head is `f39b71a826d0`. **Do not run migrations against an unknown or freshly created database by accident.**

## Verification in this build workspace

- New persistence and rollback tests passed; existing email tests passed.
- Fresh SQLite Alembic upgrade to head succeeded.
- Python syntax compilation passed.
- Framework-independent pytest subset completed successfully.
- Full Flask suite not executed because Flask is unavailable in this workspace; validate on Windows VS Code and run browser workflows before deployment.

## Further work

Add durable sanitized evidence with explicit retention/deletion controls and access policy, alert/incident linking, per-case analyst comments with richer provenance, threat enrichment with SSRF protection, and full integration tests. Do not call this release production ready.
