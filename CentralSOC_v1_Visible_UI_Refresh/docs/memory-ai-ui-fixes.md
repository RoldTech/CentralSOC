# Security Memory, AI diagnostics and SOC UI fixes

## Security Memory
The previous implementation excluded all alerts without analyst verdicts. That made an IP with detections appear to have no history. The default search now includes all alerts and labels missing verdicts as Not reviewed. Reviewed alerts only is an optional filter. Exact IP queries also search event source/destination fields and extracted indicator values, with source links. Event and indicator sections show the latest 25 matches and the full counts. Alert results remain paginated. All searches cover all stored time ranges.
An IP not ingested in this database will still return no results; the application does not invent memories or run external IP enrichment. Reviewed decisions and raw activity remain visibly distinct.

## AI
The screenshot shows Security Memory, not an AI error. The exact failure on the user's server could not be reproduced remotely. This update fixes silent configuration ambiguity and generic provider failures:
- Admins see individual enabled/key/model configuration checks and setup instructions, without exposing keys.
- Enable values 1, true, yes and on are accepted; whitespace-only key/model values are rejected.
- HTTP 400/401/403/404/429, connection failure, timeout and incomplete output have specific safe guidance. Provider bodies and credentials are not displayed.
- Output token limit is increased from 1400 to 3000 to reduce incomplete answers; some models may still require a different output/reasoning budget. There is no automatic retry.
- Local briefs still work without an API key. AI requires a valid key, model access and network access on the actual server. Configuration ready does not mean the provider connection has been tested.

For AI setup, open an alert → Investigation assistant → Server setup instructions (admin). Update .env or the server environment and restart. Existing environment variables override .env. If an AI run still fails, its new error message identifies the next check; do not send your API key in chat.

## UI
Dark navy surfaces, muted teal primary buttons, restrained blue-gray secondary buttons, soft hover states, and subdued navigation accents. Severity colors retain their meaning. The stylesheet cache version changed to soc-muted-memory-3. Restart and hard-refresh (Ctrl+F5) after updating.

## Validation and installation
623 tests passed, including unreviewed source-IP searches, exact IP matching, event-only matches, indicator links, reviewed filtering, missing data and safe AI diagnostics. AI network behavior is mocked; no live credentials were available. Browser visual checks remain unverified because the Chromium download failed.
No additional migration is required when upgrading from the immediately previous response/investigation package. Earlier packages still need the migration procedure in operations-upgrade.md. Preserve your .env, database and uploads when replacing application files. This package does not contain or modify your local production database.
