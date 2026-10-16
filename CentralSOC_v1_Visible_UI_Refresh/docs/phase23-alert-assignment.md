# Phase 23 — Alert triage ownership

## Changes
- `alerts.assigned_to`: nullable username FK to `users.username`, indexed.
- Explicit `assign_alerts` RBAC permission for ADMIN and ANALYST; VIEWER is read-only.
- Only active ANALYST or ADMIN accounts can be assigned; empty value unassigns.
- Assignment changes are transactionally audited as `ALERT_ASSIGNED` and appear in the alert timeline.
- Alert queue supports ownership filters: all, assigned to me, and unassigned.
- Alert detail shows current owner and an assignment form when authorized.

## Safe upgrade (existing installation)
1. Stop the local server and back up `.env`, `instance/`, database and evidence files. Do NOT copy the ZIP's `instance/` over your database.
2. Merge project source files and migrations into the existing source folder.
3. Activate your existing `.venv`, check that `DATABASE_URL` points to the **same existing SQLite database** used previously. Example: `$env:DATABASE_URL = 'sqlite:///instance/centralsoc-new.db'` (only if that was already the correct location).
4. Run `python -m alembic current` then `python -m alembic upgrade head` and confirm revision `c823a9d11f30`.
5. Run `python -m pytest -q`, then start `python run.py` with local dev environment settings.
6. Confirm the Alerts queue and one alert detail page work; assign and unassign an alert, review audit history.

No destructive reset and no administrator recreation should be performed. Existing rows receive NULL `assigned_to` (unassigned). The migration modifies the alerts table and may rebuild it on SQLite, so a verified backup is essential.

## Verification scope
- Targeted service tests validate assignment, active-role checks, rollback, queue filters, and RBAC.
- The available non-Flask regression subset passed; full Flask integration and Alembic execution require an environment with the missing packages.
- Does not implement multi-tenant assignment isolation, SLA timers, or notification delivery.
