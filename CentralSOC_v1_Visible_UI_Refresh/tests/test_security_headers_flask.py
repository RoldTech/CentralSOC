"""Security headers wired through an actual Flask response (Flask is a hard dependency, always present)."""

from flask import Flask

from regexsoc.web.security_headers import CSP, apply_security_headers


def make_app():
    app = Flask(__name__)

    @app.get("/x")
    def x():
        return "ok"

    @app.after_request
    def _(response):
        from flask import request
        return apply_security_headers(response, is_https=request.headers.get("X-Forwarded-Proto") == "https")

    return app


def test_headers_present_on_every_response():
    client = make_app().test_client()
    r = client.get("/x")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Content-Security-Policy"] == CSP
    assert r.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert "camera=()" in r.headers["Permissions-Policy"]
    assert r.headers["Cache-Control"] == "no-store"


def test_hsts_absent_over_plain_http():
    r = make_app().test_client().get("/x")
    assert "Strict-Transport-Security" not in r.headers


def test_hsts_present_when_request_is_secure():
    r = make_app().test_client().get("/x", headers={"X-Forwarded-Proto": "https"})
    assert "max-age=63072000" in r.headers["Strict-Transport-Security"]


def test_csp_blocks_inline_and_third_party_by_policy():
    assert "script-src 'self'" in CSP and "object-src 'none'" in CSP and "frame-ancestors 'none'" in CSP
