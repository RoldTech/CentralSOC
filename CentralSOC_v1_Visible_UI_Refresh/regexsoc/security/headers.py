"""HTTP security headers (applied to every response)."""

from __future__ import annotations

# No 'unsafe-inline' anywhere: templates must use external CSS/JS files only.
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
    "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)


def apply_security_headers(response, *, hsts: bool = False, cacheable: bool = False):
    """Set defensive headers on a Flask/Werkzeug response and return it.

    ``hsts`` should only be True when the app is served over HTTPS (browsers ignore it on HTTP, and a
    wrong HSTS value on a shared hostname is painful to undo).
    """
    h = response.headers
    h["Content-Security-Policy"] = CSP
    h["X-Content-Type-Options"] = "nosniff"
    h["X-Frame-Options"] = "DENY"
    h["Referrer-Policy"] = "no-referrer"
    h["Permissions-Policy"] = "geolocation=(), camera=(), microphone=(), payment=(), usb=()"
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    h["Cross-Origin-Resource-Policy"] = "same-origin"
    if hsts:
        h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if not cacheable:
        h["Cache-Control"] = "no-store"
        h["Pragma"] = "no-cache"
    return response
