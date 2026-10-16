"""Dashboard UI route tests: overview, alerts, events, IOCs, detections, log analysis, reports,
settings, search, notifications. Skipped automatically without SQLAlchemy.

Reuses the same app/login/CSRF pattern as test_web_app.py rather than importing from it, so this
file has no import-order dependency on that one.
"""

import io
from pathlib import Path

import pytest

pytest.importorskip("sqlalchemy")

from regexsoc.db.auth_service import create_user  # noqa: E402
from regexsoc.db.session import session_scope  # noqa: E402
from regexsoc.web import create_app  # noqa: E402
from regexsoc.web.csrf_middleware import FORM_FIELD  # noqa: E402

SAMPLE = Path(__file__).resolve().parent.parent / "sample_logs" / "ssh_auth.log"
STRONG_PW = "Correct-Horse-Battery-Staple-1"


@pytest.fixture
def app(monkeypatch, tmp_path):
    monkeypatch.setenv("REGEXSOC_ENV", "development")
    monkeypatch.setenv("REGEXSOC_SECRET_KEY", "test-only-secret-key")
    monkeypatch.setenv("REGEXSOC_UPLOAD_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("REGEXSOC_RULE_STATE", str(tmp_path / "rule_state.json"))
    flask_app = create_app(database_url="sqlite://")
    flask_app.config["TESTING"] = True
    engine = flask_app.extensions["regexsoc_engine"]
    with session_scope(engine) as s:
        create_user(s, "admin", STRONG_PW, "ADMIN")
        create_user(s, "analyst", STRONG_PW, "ANALYST")
        create_user(s, "viewer", STRONG_PW, "VIEWER")
    return flask_app


def get_csrf(client, path="/login"):
    html = client.get(path).get_data(as_text=True)
    start = html.index('name="csrf_token" value="') + len('name="csrf_token" value="')
    return html[start : html.index('"', start)]


def api_csrf_token(client) -> str:
    return client.get("/api/csrf-token").json["csrf_token"]


def login(client, username, password=STRONG_PW):
    token = get_csrf(client)
    return client.post("/login", data={"username": username, "password": password, FORM_FIELD: token})


def upload_sample(client):
    token = api_csrf_token(client)
    with open(SAMPLE, "rb") as f:
        return client.post("/log-analysis", data={"file": (f, "ssh_auth.log"), FORM_FIELD: token},
                           content_type="multipart/form-data", follow_redirects=True)


# --------------------------------------------------------------------------- overview / notifications
def test_overview_loads_and_shows_cards(app):
    client = app.test_client()
    login(client, "admin")
    r = client.get("/")
    assert r.status_code == 200
    assert b"Critical alerts" in r.data and b"Failed logins" in r.data


def test_notification_bell_count_is_correct_on_every_page_not_just_overview(app):
    """Regression test: the bell used to only get a count on the overview page."""
    client = app.test_client()
    login(client, "analyst")
    upload_sample(client)
    for path in ("/", "/alerts", "/events", "/iocs", "/rules", "/detections", "/settings"):
        r = client.get(path)
        assert r.status_code == 200
        # a critical alert (brute force) exists in the sample, so the bell should show at least 1 everywhere
        assert b"bell-badge" in r.data, f"missing notification badge on {path}"


# --------------------------------------------------------------------------- alerts
def test_alerts_page_time_range_and_detection_filters(app):
    client = app.test_client()
    login(client, "admin")
    upload_sample(client)
    assert client.get("/alerts?time_range=30d").status_code == 200
    r = client.get("/alerts?time_range=15m")  # sample data is historical; a 15-minute window excludes it
    assert r.status_code == 200 and b"No alerts match" in r.data
    r = client.get("/alerts?rule_id=RULE-002")
    assert r.status_code == 200 and b"SSH Brute Force" in r.data


def test_alert_detail_shows_detection_information(app):
    client = app.test_client()
    login(client, "admin")
    upload_sample(client)
    alert_id = client.get("/alerts?severity=CRITICAL").data  # locate via HTML link
    import re
    match = re.search(rb'/alerts/(\d+)"', alert_id)
    assert match, "no alert link found on the alerts page"
    r = client.get(f"/alerts/{match.group(1).decode()}")
    assert r.status_code == 200
    assert b"Occurrences" in r.data and b"First seen" in r.data and b"Event timeline" in r.data


# --------------------------------------------------------------------------- events
def test_events_page_destination_ip_filter_does_not_error(app):
    client = app.test_client()
    login(client, "viewer")
    upload_sample(client)
    assert client.get("/events?destination_ip=10.0.0.5").status_code == 200


# --------------------------------------------------------------------------- detections
def test_detections_list_and_detail(app):
    client = app.test_client()
    login(client, "admin")
    upload_sample(client)
    r = client.get("/detections")
    assert r.status_code == 200 and b"SSH Brute Force" in r.data
    r = client.get("/detections/RULE-002")
    assert r.status_code == 200 and b"What this detects" in r.data


def test_unknown_detection_rule_is_404(app):
    client = app.test_client()
    login(client, "admin")
    assert client.get("/detections/RULE-999").status_code == 404


# --------------------------------------------------------------------------- IOCs (aggregated)
def test_iocs_page_shows_occurrences_and_risk(app):
    client = app.test_client()
    login(client, "admin")
    upload_sample(client)
    r = client.get("/iocs?type=IPV4")
    assert r.status_code == 200 and b"Occurrences" in r.data


def test_ioc_detail_by_type_and_value(app):
    client = app.test_client()
    login(client, "admin")
    upload_sample(client)
    r = client.get("/iocs/IPV4/203.0.113.50")
    assert r.status_code == 200 and b"related alert" in r.data.lower()


def test_ioc_detail_unknown_value_is_404(app):
    client = app.test_client()
    login(client, "admin")
    assert client.get("/iocs/IPV4/198.51.100.254").status_code == 404


# --------------------------------------------------------------------------- log analysis (dashboard upload)
def test_log_analysis_upload_and_result_reuse_the_same_validated_pipeline(app):
    client = app.test_client()
    login(client, "analyst")
    r = upload_sample(client)
    assert r.status_code == 200
    assert b"Total events" in r.data and b"Parsed events" in r.data


def test_log_analysis_rejects_bad_extension_same_as_api(app):
    client = app.test_client()
    login(client, "analyst")
    token = api_csrf_token(client)
    # io.BytesIO (not a bare bytes literal) avoids a Werkzeug test-client quirk where a raw-bytes
    # file tuple can lose its filename when mixed with another plain form field in the same dict.
    post_resp = client.post("/log-analysis", data={"file": (io.BytesIO(b"bad"), "x.exe"), FORM_FIELD: token},
                            content_type="multipart/form-data")
    r = client.get(post_resp.headers.get("Location", "/log-analysis"))
    assert b"unsupported file extension" in r.data.lower()


def test_viewer_cannot_reach_log_analysis(app):
    client = app.test_client()
    login(client, "viewer")
    assert client.get("/log-analysis").status_code == 403


# --------------------------------------------------------------------------- reports
def test_reports_page_lists_permitted_datasets(app):
    client = app.test_client()
    login(client, "viewer")
    r = client.get("/reports")
    assert r.status_code == 200 and b"Alerts" in r.data


def test_reports_export_csv_and_json(app):
    client = app.test_client()
    login(client, "admin")
    upload_sample(client)
    r = client.get("/reports/export/alerts.csv")
    assert r.status_code == 200 and r.mimetype == "text/csv" and b"rule_id" in r.data
    r = client.get("/reports/export/alerts.json")
    assert r.status_code == 200 and r.mimetype == "application/json"


def test_reports_export_unknown_dataset_is_404(app):
    client = app.test_client()
    login(client, "admin")
    assert client.get("/reports/export/bogus.csv").status_code == 404


# --------------------------------------------------------------------------- settings
def test_settings_page_shows_account_no_secrets(app):
    client = app.test_client()
    login(client, "admin")
    r = client.get("/settings")
    assert r.status_code == 200 and b"admin" in r.data
    assert b"password_hash" not in r.data and STRONG_PW.encode() not in r.data


def test_change_password_wrong_current_password_is_rejected(app):
    client = app.test_client()
    login(client, "admin")
    token = api_csrf_token(client)
    r = client.post("/settings/password", data={"current_password": "wrong", "new_password": "New-Strong-Pass-1",
                                                 FORM_FIELD: token}, follow_redirects=True)
    assert b"incorrect" in r.data.lower()


def test_change_password_success_then_old_password_no_longer_works(app):
    client = app.test_client()
    login(client, "admin")
    token = api_csrf_token(client)
    new_pw = "A-New-Strong-Passphrase-9"
    client.post("/settings/password", data={"current_password": STRONG_PW, "new_password": new_pw,
                                             FORM_FIELD: token})
    logout_token = api_csrf_token(client)
    client.post("/logout", data={FORM_FIELD: logout_token})
    r = login(client, "admin", STRONG_PW)
    assert client.get("/api/whoami").status_code == 401
    r = login(client, "admin", new_pw)
    assert client.get("/api/whoami").status_code == 200

# --------------------------------------------------------------------------- batch log ingestion
def test_log_analysis_batch_partial_success_and_duplicate(app):
    client = app.test_client()
    login(client, "admin")
    token = api_csrf_token(client)
    sample_bytes = SAMPLE.read_bytes()
    response = client.post(
        "/log-analysis",
        data={"file": [(io.BytesIO(sample_bytes), "first.log"),
                       (io.BytesIO(sample_bytes), "duplicate.log"),
                       (io.BytesIO(b"invalid"), "disallowed.exe")], FORM_FIELD: token},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    assert b"Batch log analysis results" in response.data
    assert b"first.log" in response.data and b"duplicate.log" in response.data
    assert b"Duplicate (already ingested)" in response.data
    assert b"disallowed.exe" in response.data and b"Rejected" in response.data
    from sqlalchemy import func, select
    from regexsoc.db.models import LogFile
    with session_scope(app.extensions["regexsoc_engine"]) as db:
        assert db.scalar(select(func.count()).select_from(LogFile)) == 1


def test_log_analysis_batch_rejects_more_than_eight_files(app):
    client = app.test_client()
    login(client, "admin")
    token = api_csrf_token(client)
    response = client.post(
        "/log-analysis",
        data={"file": [(io.BytesIO(b"test"), f"sample{i}.log") for i in range(9)], FORM_FIELD: token},
        content_type="multipart/form-data", follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"at most 8 files" in response.data
    from sqlalchemy import func, select
    from regexsoc.db.models import LogFile
    with session_scope(app.extensions["regexsoc_engine"]) as db:
        assert db.scalar(select(func.count()).select_from(LogFile)) == 0


def test_log_analysis_batch_respects_role_permissions(app):
    client = app.test_client()
    login(client, "viewer")
    token = api_csrf_token(client)
    response = client.post(
        "/log-analysis", data={"file": [(io.BytesIO(b"test"), "a.log")], FORM_FIELD: token},
        content_type="multipart/form-data",
    )
    assert response.status_code == 403
