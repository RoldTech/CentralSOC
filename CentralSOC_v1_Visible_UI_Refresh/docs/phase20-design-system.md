# Phase 20 — SOC design consistency and triage UX

- Shared semantic tokens in `regexsoc/web/static/css/app.css` for surfaces, typography, severity, states and controls.
- Alert queue uses a labelled filter panel, accessible table caption, and actionable empty state.
- Incident queue uses semantic severity/status treatments and an accessible table wrapper.
- Incident details use the same workspace heading and state badges.
- Alert detail removes a duplicate activity panel that repeated the same form ID.
- No changes to routes, permissions, database models, or migrations.

## Verification limits

Jinja syntax and available pytest subset are checked here; live browser validation and Flask integration should be run on the local environment. Back up your project and preserve `.env`, `.venv`, `instance`, and uploaded evidence when updating.
