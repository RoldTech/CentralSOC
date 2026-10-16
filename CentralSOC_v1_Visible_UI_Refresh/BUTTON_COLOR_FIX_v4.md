# Exact Create incident button color fix — v4

All primary buttons now use the screenshot reference: background #174951, border #399eaa, text #e4f8fa. This covers alert export and filtering, memory search, detections, events, IOCs, log/email analysis, rules filters, settings, investigation and response forms, and sign-in. Secondary and destructive controls retain their own semantics.

The new buttons-create-incident-v4.css loads last and explicitly overrides prior primary-button color rules. No database migration or configuration change is required for this color fix. The previous AI/Memory fixes are included.

## Apply to the application you actually run
1. Stop the running CentralSOC server (Ctrl+C in its terminal).
2. Extract this ZIP. Copy the contents of its CentralSOC_v1_Visible_UI_Refresh folder into the existing application folder containing the run.py you use. Replace application files, including regexsoc/web/templates/base.html and the entire regexsoc/web/static/css folder. Preserve .env, instance/, your database and uploads. Do not simply extract a second copy beside the application and start the original copy.
3. From that updated application folder, run python run.py using your usual environment.
4. Reload the browser (Ctrl+F5).

## Verify the actual running copy
Open http://127.0.0.1:5000/static/css/buttons-create-incident-v4.css . It must show background: #174951 !important. A 404 means the running application is using a different or incomplete folder.
View page source and find buttons-create-incident-v4.css and button-match-v4. If missing, the running process has not loaded the updated base.html; check the folder and restart it.
The screenshots supplied still show the older Decision archive wording, while the previous update uses Search security history. This indicates older templates were being served, not just a button-color mismatch. A hard refresh cannot replace old server-side files.

The button RGB fill was sampled directly from the supplied screenshot: (23, 73, 81). Browser rendering has not been verified in this environment.
