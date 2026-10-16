# Phase 21 — Alert investigation workspace

- Added quick navigation within alert details, links to scoped event searches, a bounded cross-file related-telemetry panel, and links to associated incidents.
- Related telemetry is **not detection evidence**: matches are based on the same source IP OR username in **other files**, not automatic correlation or a threat verdict.
- Access to linked events and incidents remains guarded by `view_events` and `view_incidents` server-side permissions; updates still require `update_alert_status` and CSRF.
- Read-only queries are limited (25 telemetry records, 20 incidents) and do not alter existing audit or normalized data.
- No migration required. Full Flask/browser integration must be tested locally with installed dependencies.
