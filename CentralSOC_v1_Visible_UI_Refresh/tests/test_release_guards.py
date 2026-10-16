"""Release security regressions that run even without Flask installed."""
from pathlib import Path

from regexsoc.security.audit import AuditAction
from regexsoc.services.export import to_csv


def test_all_csv_exports_keep_formula_protection():
    assert "'=HYPERLINK" in to_csv([{"title": '=HYPERLINK("https://example.invalid")'}], ["title"])


def test_report_export_routes_enforce_auditing_and_no_store():
    source = (Path(__file__).resolve().parents[1] / "regexsoc/web/routes/dashboard.py").read_text()
    assert "AuditAction.REPORT_EXPORTED" in source
    assert '"Cache-Control": "no-store"' in source
    assert '"X-Content-Type-Options": "nosniff"' in source
    assert AuditAction.REPORT_EXPORTED == "REPORT_EXPORTED"


def test_incident_export_requires_permission_and_audit():
    source = (Path(__file__).resolve().parents[1] / "regexsoc/web/routes/incidents.py").read_text()
    assert '@permission_required("view_incidents")\ndef export_incidents' in source
    assert "AuditAction.INCIDENTS_EXPORTED" in source
    assert AuditAction.INCIDENTS_EXPORTED == "INCIDENTS_EXPORTED"


def test_readiness_is_database_aware_and_non_disclosing():
    source = (Path(__file__).resolve().parents[1] / "regexsoc/web/__init__.py").read_text()
    assert '@app.get("/readyz")' in source
    assert 'connection.execute(text("SELECT 1"))' in source
    assert 'return jsonify(status="unavailable"), 503' in source
