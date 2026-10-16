"""Flask application factory.

SQLAlchemy is imported lazily inside ``create_app`` so importing this package, or unit-testing the
framework-light helpers (security headers, CSRF logic), never requires it to be installed.
"""

from __future__ import annotations

from datetime import timedelta

from regexsoc import config
from regexsoc.web.csrf_middleware import FORM_FIELD, HEADER_NAME, csrf_allows
from regexsoc.web.security_headers import apply_security_headers


def create_app(database_url: str | None = None) -> Flask:
    # Keep framework-light helper modules importable without Flask installed.
    from flask import Flask, g, jsonify, request, session

    try:
        from sqlalchemy.orm import Session
    except ImportError as exc:
        raise RuntimeError('the web app needs SQLAlchemy: pip install "SQLAlchemy>=2.0"') from exc

    from regexsoc.db.session import init_db, make_engine

    app = Flask(__name__)
    app.config["SECRET_KEY"] = config.secret_key()
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=not config.is_development(),
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=config.session_lifetime_minutes()),
        SESSION_REFRESH_EACH_REQUEST=True,  # idle timeout: the cookie's expiry slides forward each request
        MAX_CONTENT_LENGTH=max(config.max_upload_bytes(), min(2 * config.max_upload_bytes(), 100 * 1024 * 1024)) + 65536,  # bounded multipart batch overhead
        JSON_SORT_KEYS=False,
    )

    engine = make_engine(database_url)
    init_db(engine)
    app.extensions["regexsoc_engine"] = engine

    from regexsoc.db import models
    from regexsoc.security.rbac import is_valid_role

    @app.before_request
    def _open_db_session_and_load_user():
        g.db = Session(engine, expire_on_commit=False)
        g.current_user = None
        user_id = session.get("user_id")
        if user_id is not None:
            user = g.db.get(models.User, user_id)
            if user is not None and user.is_active and is_valid_role(user.role):
                g.current_user = user
            else:
                session.clear()  # stale/invalid session (deleted or disabled user)

    @app.before_request
    def _enforce_csrf():
        submitted = request.form.get(FORM_FIELD) or request.headers.get(HEADER_NAME)
        if not csrf_allows(session, app.config["SECRET_KEY"], request.method, submitted):
            # Don't touch g.db here: teardown_request always closes it, whether or not a
            # before_request handler short-circuited the response.
            return jsonify(error="CSRF token missing or invalid") if request.path.startswith("/api/") \
                else ("CSRF token missing or invalid", 400)

    @app.teardown_request
    def _close_db_session(exc):
        db = g.pop("db", None)
        if db is not None:
            try:
                # A handled 4xx/5xx response does not raise an exception in Flask.
                # Never persist pending writes from unsuccessful requests.
                if exc is not None or g.get("_rollback_request", False):
                    db.rollback()
                else:
                    db.commit()
            finally:
                db.close()

    @app.after_request
    def _add_security_headers(response):
        if response.status_code >= 400:
            g._rollback_request = True
        return apply_security_headers(response, is_https=request.is_secure)

    def _json_error(status: int, message: str):
        def handler(_exc):
            return jsonify(error=message), status
        return handler

    for status, message in ((400, "bad request"), (401, "authentication required"),
                            (403, "forbidden"), (404, "not found"), (405, "method not allowed"),
                            (413, "payload too large"), (429, "too many requests"),
                            (500, "internal server error")):
        app.register_error_handler(status, _json_error(status, message))

    from regexsoc.web.routes import api, auth, dashboard, email_security, incidents, operations

    app.register_blueprint(auth.bp)
    app.register_blueprint(dashboard.bp)
    app.register_blueprint(api.bp)
    app.register_blueprint(email_security.bp)
    app.register_blueprint(incidents.bp)
    app.register_blueprint(operations.bp)

    @app.template_filter("activity_summary")
    def activity_summary(detail, action):
        """Present known audit payloads readably; never render details as HTML."""
        import json
        try:
            values = json.loads(detail) if detail else {}
        except (ValueError, TypeError):
            return detail or "Action recorded"
        if not isinstance(values, dict):
            return detail or "Action recorded"
        if action == "ALERT_ASSIGNED":
            return f"Ownership changed: {values.get('from') or 'Unassigned'} → {values.get('to') or 'Unassigned'}"
        if action == "ALERT_VERDICT_SET":
            return f"Assessment: {str(values.get('to') or '').replace('_', ' ')} — {values.get('reason') or ''}"
        if action == "ALERT_STATUS_CHANGED":
            return f"Status updated: {values.get('from') or 'Unknown'} → {values.get('to') or 'Unknown'}"
        if action == "ALERT_NOTE_ADDED":
            return str(values.get('note') or values.get('text') or detail or 'Note recorded')
        return detail or "Action recorded"

    @app.template_filter("combine_page")
    def combine_page(args: dict, page: int) -> dict:
        return {**args, "page": page}

    @app.get("/healthz")
    def healthz():
        """Liveness check: process and Flask routing are responsive."""
        return jsonify(status="ok")

    @app.get("/readyz")
    def readyz():
        """Readiness check: database can execute a simple query; no schema or secrets exposed."""
        from sqlalchemy import text
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
        except Exception:
            app.logger.exception("Database readiness check failed")
            return jsonify(status="unavailable"), 503
        return jsonify(status="ready")

    return app
