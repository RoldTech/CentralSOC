# CentralSOC v1.0 — Screen review fixes

This release-candidate increment addresses observed display bugs only.

- Alerts queue column header changed from **Score** to **Risk Score**.
- Replaced HTML-entity strings in Jinja expressions (`'&mdash;'`) with the real em dash (`'—'`). Autoescaping remains enabled for user-supplied evidence.
- Replaced ambiguous example-IP filter placeholders with explicit filter hints.
- Added accessible focus-only styling to the skip-to-main-content link.
- Topbar now uses known endpoint names for module-specific titles where no explicit title was set.

## Limitations and validation gates

- **Timestamps:** Historic imported event timestamps are not changed; they can be intentionally older than ingestion dates. Their origin and timezone normalization require source-by-source integration review before the release is approved.
- **Database:** No schema migration or database changes in this increment.
- **Full application verification:** Run `python -m pytest -q` with Flask installed, then manually exercise Alerts, Events, Log Analysis, and navigation.
- **Deployments:** Do not deploy to production until threat model, authorization tests, backup/restore and deployment verification are completed.
