"""Security headers applied to every response.

Framework-light on purpose: ``apply_security_headers`` only needs an object with a ``.headers``
mapping (a Flask/Werkzeug Response satisfies this), so it is directly unit-testable.
"""

from __future__ import annotations

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; "
    "frame-ancestors 'none'; form-action 'self'"
)

STATIC_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",  # defense in depth alongside the CSP frame-ancestors directive
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Content-Security-Policy": CSP,
    "Cache-Control": "no-store",  # this app is all dynamic, sensitive data; nothing should be cached
}


def apply_security_headers(response, is_https: bool):
    """Add security headers to a response. HSTS is added only over HTTPS (it is meaningless, and
    can be actively harmful in local development, over plain HTTP)."""
    for name, value in STATIC_HEADERS.items():
        response.headers[name] = value
    if is_https:
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response
