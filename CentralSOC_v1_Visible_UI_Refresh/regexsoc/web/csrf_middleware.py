"""CSRF enforcement as a plain function, so it is testable without a running Flask app.

Pattern: a random per-session ID is created on first contact (``session["_sid"]``) and signed into a
token via regexsoc.security.csrf. The token must be echoed back on any unsafe request, either as a
form field (``csrf_token``) or a header (``X-CSRFToken``, for the future JSON dashboard).
"""

from __future__ import annotations

import secrets

from regexsoc.security.csrf import issue_token, verify_token

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
SESSION_ID_KEY = "_sid"
FORM_FIELD = "csrf_token"
HEADER_NAME = "X-CSRFToken"


def ensure_session_id(session: dict) -> str:
    """Get or create the per-session random ID that CSRF tokens are bound to."""
    sid = session.get(SESSION_ID_KEY)
    if not sid:
        sid = secrets.token_urlsafe(16)
        session[SESSION_ID_KEY] = sid
    return sid


def current_token(session: dict, secret_key: str) -> str:
    """The CSRF token for the current session, for embedding in forms/JS."""
    return issue_token(secret_key, ensure_session_id(session))


def csrf_allows(session: dict, secret_key: str, method: str, submitted_token: str | None) -> bool:
    """True if the request should proceed. Safe methods always pass; unsafe methods need a valid token."""
    if method.upper() in SAFE_METHODS:
        return True
    sid = session.get(SESSION_ID_KEY)
    if not sid:
        return False  # no session was ever issued a token, so nothing could be valid
    return verify_token(secret_key, sid, submitted_token)
