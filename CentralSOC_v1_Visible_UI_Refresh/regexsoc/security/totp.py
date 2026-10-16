"""TOTP (RFC 6238) multi-factor authentication built on PyOTP, with replay protection."""

from __future__ import annotations

import hmac
import re
import time

INTERVAL = 30
DIGITS = 6
ISSUER = "RegexSOC"
_CODE = re.compile(r"\d{6}")


def normalize_code(code: str | None) -> str | None:
    """Strip spaces/dashes; return the 6-digit code or None if malformed."""
    cleaned = re.sub(r"[\s-]", "", code or "")
    return cleaned if _CODE.fullmatch(cleaned) else None


def current_step(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // INTERVAL)


def generate_secret() -> str:
    import pyotp

    return pyotp.random_base32()


def provisioning_uri(secret: str, username: str, issuer: str = ISSUER) -> str:
    import pyotp

    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def verify_totp(secret: str, code: str | None, last_used_step: int | None = None,
                now: float | None = None, window: int = 1) -> int | None:
    """Return the matched time step, or None.

    Accepts codes from ``window`` steps either side (clock drift). A step at or before
    ``last_used_step`` is rejected, so a captured code cannot be replayed.
    """
    import pyotp

    normalized = normalize_code(code)
    if normalized is None:
        return None
    totp = pyotp.TOTP(secret, digits=DIGITS, interval=INTERVAL)
    center = current_step(now)
    matched: int | None = None
    for step in range(center - window, center + window + 1):
        expected = totp.at(step * INTERVAL)
        if hmac.compare_digest(expected, normalized) and (last_used_step is None or step > last_used_step):
            matched = step  # keep looping: no early exit
    return matched
