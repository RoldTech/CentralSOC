"""CSRF protection: a signed double-submit token, using itsdangerous (already a Flask dependency).

Deviation from the spec's suggestion of Flask-WTF: Flask-WTF is a thin layer over exactly this
pattern, and implementing it directly avoids an extra dependency while staying framework-agnostic
and unit-testable without a request context.
"""

from __future__ import annotations

import base64
import binascii

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

TOKEN_MAX_AGE_SECONDS = 4 * 3600
_SALT = "regexsoc-csrf"


def issue_token(secret_key: str, session_id: str) -> str:
    """A signed token bound to ``session_id``. Store this token in the session and hand it to forms/JS."""
    return URLSafeTimedSerializer(secret_key, salt=_SALT).dumps(session_id)


def verify_token(secret_key: str, session_id: str, submitted_token: str | None) -> bool:
    """True only if the token verifies, is unexpired, and matches this session."""
    if not submitted_token:
        return False
    # Require canonical base64url encoding: changing unused trailing bits can
    # produce a different string that decodes to the same valid signature.
    try:
        parts = submitted_token.split(".")
        if len(parts) != 3:
            return False
        for part in parts:
            encoded = part.encode("ascii")
            decoded = base64.b64decode(encoded + b"=" * (-len(encoded) % 4),
                                       altchars=b"-_", validate=True)
            if base64.urlsafe_b64encode(decoded).rstrip(b"=") != encoded:
                return False
    except (UnicodeEncodeError, ValueError, binascii.Error):
        return False
    try:
        payload = URLSafeTimedSerializer(secret_key, salt=_SALT).loads(
            submitted_token, max_age=TOKEN_MAX_AGE_SECONDS
        )
    except (BadSignature, SignatureExpired):
        return False
    return payload == session_id
