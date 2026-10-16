# CentralSOC v1 role model

Role identifiers: VIEWER, ANALYST (legacy), SOC_L1, SOC_L2, SOC_L3, SOC_MANAGER, ADMIN.

The legacy ANALYST role remains supported to avoid breaking existing accounts. New analyst users should use SOC_L1, SOC_L2, or SOC_L3. SOC_MANAGER manages assignments and incidents, but not user accounts. ADMIN has full platform permissions. Access is enforced through the existing server-side permission decorators. Alert assignment only accepts active eligible users.

## Upgrade safely

Back up the SQLite database and environment files. Confirm DATABASE_URL and `python -m alembic current -v` before migrating. Stop the Flask server and run `python -m alembic upgrade head`, then `python -m pytest -q`. On an existing admin account, run `python -m regexsoc users create analyst01 --role SOC_L1` (you will be prompted for a password). Existing ANALYST accounts are not automatically converted.

A downgrade refuses to proceed while any account uses a newly introduced role. The user-role table is recreated as part of the SQLite-compatible constraint migration; perform and verify backups before running it on an existing database.

## Boundaries

This release does not implement separate permissions for every L1/L2/L3 activity (e.g. incident read-vs-escalate or rule editing-vs-enabling). Validate routes and authorization in the full Flask integration suite before production use. The legacy permission name `manage_incidents` permits the existing incident management actions. No automatic network containment is introduced.
