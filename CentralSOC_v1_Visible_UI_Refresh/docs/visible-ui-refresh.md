# CentralSOC visible UI refresh

This update makes the overview page structurally different (prominent SOC overview header, 4-column priority cards, enhanced telemetry panels) while keeping existing backend logic and user data intact. It also adds a versioned CSS URL to avoid stale browser cache. Other pages receive the shared SOC palette.

Install: back up working project; stop Flask; copy `regexsoc/web/templates/base.html`, `regexsoc/web/templates/dashboard/overview.html` and `regexsoc/web/static/css/app.css` into the corresponding paths in your live application. Restart Flask; reload with Ctrl+Shift+R. Confirm page title is **Security Overview**; if it still says **Overview**, you are running another project folder or the files were not replaced. No database migration.
