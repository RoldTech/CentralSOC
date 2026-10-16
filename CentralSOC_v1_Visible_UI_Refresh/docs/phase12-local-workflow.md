# Phase 12 — Safer local development workflow

Do not extract each CentralSOC update into a new active project and expect the old
`.env`, `instance/` database, user accounts, and uploaded files to follow. Those
items are intentionally excluded from the release ZIP. Keep the working project
folder, back up its database, and merge reviewed source changes into it. Never
replace or delete `instance/` or `.env` when upgrading.

On Windows, in the existing CentralSOC folder:

```powershell
.\.venv\Scripts\python.exe -m regexsoc.doctor
.\scripts\start-dev.ps1
```

Before using `start-dev.ps1`, set `REGEXSOC_ENV=development`, a long random
`REGEXSOC_SECRET_KEY`, and `DATABASE_URL` pointing to the existing database
in `.env`. Do not paste your secret into chat or commit `.env`. Start with the
same project folder you used successfully, not a newly extracted ZIP.

The setup checker uses SQLite read-only mode and never creates or stamps a
database. A warning requires manual review; do not fix it by recreating the
existing data. Database migration compatibility and production deployment need
separate validation. This script is for local development only.
