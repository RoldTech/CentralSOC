# Phase 8 — Manual incident response playbooks

Added a curated catalog of four analyst-controlled playbooks: brute-force, phishing, suspected account compromise, and suspicious network communication. Each contains a trigger, triage, evidence, validation, containment guidance, recovery guidance, and closure checklist.

Incident detail UI permits authorized analysts to select a checklist and acknowledge steps. Each selection and step acknowledgement is written to the existing incident audit log with actor and timestamp. Changing playbooks starts a fresh checklist; repeat acknowledgements are idempotent. Audit records are transactional. This is **not** evidence that a containment action actually occurred, and no step invokes a third-party system.

Routes reuse existing `manage_incidents` RBAC enforcement and CSRF middleware. No database migration is required because progress is reconstructed from existing audit records.

## Validation

Targeted tests: `python -m pytest -q tests/test_playbooks.py tests/test_incidents.py tests/test_incident_web_contract.py` (10 passed).

Other runnable tests: `python -m pytest -q --ignore=tests/test_web.py --ignore=tests/test_email_web.py --ignore=tests/test_incident_routes.py --ignore=tests/test_security_headers_flask.py --ignore=tests/test_web_app.py` (see test result report).

Flask integration remains unverified due to missing Flask in this execution environment. Audit-derived progress is not a tamper-proof ledger, nor is it optimized for very long incident histories. Future increments should introduce persistent playbook execution models, completion commentary and approval tracking.
