# Phase 28 — Email forensic metadata triage

## Delivered

- Offline bounded link extraction from plaintext and HTML anchor elements.
- Review flags for HTTP links, literal-IP links, and misleading visible-URL host mismatches.
- Attachment filename extension and double-extension heuristics.
- Message parser-defect signal and a separate analyst-readable forensic panel.
- Bounded processing (100,000 characters per body, 100 candidate hosts, 100 attachments, 200 output findings).
- Four new deterministic tests. No database migration.

## Security boundaries

No outbound HTTP, DNS, malware scanning, attachment execution, or file detonation. Forensic metadata flags are NOT used to assert maliciousness. Existing email-verdict scoring is unchanged. SPF/DKIM/DMARC are derived from message-provided headers and local alignment logic, not independently authenticated. All displayed findings are Jinja-escaped. Results are still not persisted.

## Verification

Run `python -m pytest -q tests/test_email_*.py` and `python -m pytest -q` with full dependencies on Windows. Offline email tests and template syntax were validated in the packaging environment; full Flask runtime/browser flow requires local testing.

## Future work

Add durable case storage with explicit retention and encryption controls, trusted-receiver Authentication-Results validation, optional safe threat intelligence reputation providers, verifiable attachment hashing with careful memory bounds, analyst confirmation, and evidence linking to cases.
