"""End-to-end Flask app tests: login, MFA, RBAC, CSRF, upload, API. Skipped without SQLAlchemy."""

from pathlib import Path

import pytest

pytest.importorskip("sqlalchemy")

from regexsoc.db.auth_service import begin_mfa_enrollment, confirm_mfa_enrollment, create_user  # noqa: E402
from regexsoc.db.session import make_engine, session_scope  # noqa: E402
from regexsoc.security.mfa import totp_now  # noqa: E402
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
    app = create_app(database_url="sqlite://")
    app.config["TESTING"] = True
    engine = app.extensions["regexsoc_engine"]
    with session_scope(engine) as s:
        create_user(s, "admin", STRONG_PW, "ADMIN")
        create_user(s, "analyst", STRONG_PW, "ANALYST")
        create_user(s, "viewer", STRONG_PW, "VIEWER")
    return app


def get_csrf(client, path="/login"):
    """Extract a token from a rendered HTML form. Only valid for anonymous, pre-login pages
    (/login, /login/mfa): once logged in, GET /login just redirects and has no form to parse.
    Use api_csrf_token() for an already-authenticated client."""
    html = client.get(path).get_data(as_text=True)
    start = html.index('name="csrf_token" value="') + len('name="csrf_token" value="')
    return html[start : html.index('"', start)]


def api_csrf_token(client) -> str:
    """A fresh CSRF token via /api/csrf-token, which works whether or not the client is logged in."""
    return client.get("/api/csrf-token").json["csrf_token"]


def login(client, username, password=STRONG_PW):
    token = get_csrf(client)
    return client.post("/login", data={"username": username, "password": password, FORM_FIELD: token})


def test_healthz_needs_no_auth(app):
    assert app.test_client().get("/healthz").status_code == 200


def test_index_requires_login(app):
    r = app.test_client().get("/")
    assert r.status_code in (302, 401)


def test_successful_login_reaches_index(app):
    client = app.test_client()
    r = login(client, "admin")
    assert r.status_code == 302
    assert client.get("/").status_code == 200


def test_wrong_password_shows_error_and_does_not_log_in(app):
    client = app.test_client()
    r = login(client, "admin", "totally-wrong")
    assert r.status_code == 302  # redirect back to /login with a flash
    assert client.get("/api/whoami").status_code == 401


def test_missing_csrf_token_is_rejected(app):
    client = app.test_client()
    r = client.post("/login", data={"username": "admin", "password": STRONG_PW})
    assert r.status_code == 400


def test_account_locks_after_repeated_failures(app, monkeypatch):
    monkeypatch.setenv("REGEXSOC_LOCKOUT_MAX_FAILURES", "3")
    monkeypatch.setenv("REGEXSOC_LOCKOUT_WINDOW_MINUTES", "15")
    client = app.test_client()
    for _ in range(3):
        login(client, "admin", "wrong")
    r = login(client, "admin", STRONG_PW)  # correct password, but now locked
    assert r.status_code == 302
    assert client.get("/api/whoami").status_code == 401


def test_mfa_login_flow(app):
    engine = app.extensions["regexsoc_engine"]
    with session_scope(engine) as s:
        from sqlalchemy import select
        from regexsoc.db import models
        uid = s.scalar(select(models.User).where(models.User.username == "analyst")).id
        secret, _ = begin_mfa_enrollment(s, uid)
        confirm_mfa_enrollment(s, uid, totp_now(secret))

    client = app.test_client()
    login(client, "analyst")
    assert client.get("/api/whoami").status_code == 401  # not fully authenticated yet
    token = get_csrf(client, "/login/mfa")
    r = client.post("/login/mfa", data={"code": totp_now(secret), FORM_FIELD: token})
    assert r.status_code == 302
    assert client.get("/api/whoami").json["username"] == "analyst"


def test_logout_ends_the_session(app):
    client = app.test_client()
    login(client, "admin")
    assert client.get("/").status_code == 200
    token = api_csrf_token(client)  # post-login: /login now just redirects, so use the API endpoint
    client.post("/logout", data={FORM_FIELD: token})
    assert client.get("/").status_code in (302, 401)


def test_rbac_viewer_cannot_upload_or_manage_rules(app):
    client = app.test_client()
    login(client, "viewer")
    assert client.get("/api/events").status_code == 200
    assert client.patch("/api/rules/RULE-001", json={"enabled": False},
                        headers={"X-CSRFToken": api_csrf_token(client)}).status_code == 403


def test_rbac_analyst_cannot_manage_rules_but_can_upload(app):
    client = app.test_client()
    login(client, "analyst")
    token = api_csrf_token(client)
    assert client.patch("/api/rules/RULE-001", json={"enabled": False},
                        headers={"X-CSRFToken": token}).status_code == 403
    with open(SAMPLE, "rb") as f:
        r = client.post("/api/logs/upload", data={"file": (f, "ssh_auth.log")},
                        headers={"X-CSRFToken": token}, content_type="multipart/form-data")
    assert r.status_code == 201 and r.json["events"] > 0


def test_admin_can_manage_rules(app):
    client = app.test_client()
    login(client, "admin")
    token = api_csrf_token(client)
    r = client.patch("/api/rules/RULE-001", json={"enabled": False}, headers={"X-CSRFToken": token})
    assert r.status_code == 200 and r.json["enabled"] is False


def test_upload_rejects_bad_extension(app):
    client = app.test_client()
    login(client, "analyst")
    token = api_csrf_token(client)
    r = client.post("/api/logs/upload", data={"file": (b"malicious", "x.exe")},
                    headers={"X-CSRFToken": token}, content_type="multipart/form-data")
    assert r.status_code == 400


def test_full_pipeline_upload_then_alerts_then_patch_status(app):
    client = app.test_client()
    login(client, "analyst")
    token = api_csrf_token(client)
    with open(SAMPLE, "rb") as f:
        client.post("/api/logs/upload", data={"file": (f, "ssh_auth.log")},
                   headers={"X-CSRFToken": token}, content_type="multipart/form-data")
    alerts = client.get("/api/alerts?severity=critical").json["alerts"]
    assert alerts
    alert_pk = alerts[0]["id"]
    r = client.patch(f"/api/alerts/{alert_pk}", json={"status": "investigating"},
                     headers={"X-CSRFToken": token})
    assert r.status_code == 200 and r.json["status"] == "Investigating"


def test_statistics_endpoint(app):
    client = app.test_client()
    login(client, "viewer")
    r = client.get("/api/statistics")
    assert r.status_code == 200 and "alerts_by_severity" in r.json


def test_404_on_missing_event(app):
    client = app.test_client()
    login(client, "viewer")
    assert client.get("/api/events/99999").status_code == 404


def test_security_headers_present_on_api_response(app):
    client = app.test_client()
    login(client, "viewer")
    r = client.get("/api/whoami")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["Content-Security-Policy"]


def test_error_response_rolls_back_pending_database_changes(app):
    """Handled HTTP errors must not commit changes made before returning the error."""
    from flask import g
    from sqlalchemy import select
    from regexsoc.db import models

    engine = app.extensions["regexsoc_engine"]
    with session_scope(engine) as db:
        user_id = db.scalar(select(models.User).where(models.User.username == "viewer")).id

    @app.get("/_test/rollback-on-error")
    def rollback_on_error():
        user = g.db.get(models.User, user_id)
        user.is_active = False
        return {"error": "intentional failure"}, 400

    response = app.test_client().get("/_test/rollback-on-error")
    assert response.status_code == 400
    with session_scope(engine) as db:
        assert db.get(models.User, user_id).is_active is True
