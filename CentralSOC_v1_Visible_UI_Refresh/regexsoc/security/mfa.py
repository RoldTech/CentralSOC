"""TOTP multi-factor authentication (RFC 6238 / RFC 4226), implemented with the standard library only.

Compatible with any standard authenticator app (Google Authenticator, Authy, 1Password...) and with
the ``pyotp`` library if it is installed elsewhere, since both implement the same RFC.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

DEFAULT_STEP = 30
DEFAULT_DIGITS = 6
DEFAULT_WINDOW = 1  # accept the previous/next 30s step, to tolerate clock drift


def generate_secret(length: int = 20) -> str:
    """A random Base32 secret (RFC 4648), the standard TOTP secret encoding."""
    return base64.b32encode(secrets.token_bytes(length)).decode("ascii").rstrip("=")


def _hotp(secret: str, counter: int, digits: int) -> str:
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF) % (10**digits)
    return str(code).zfill(digits)


def totp_now(secret: str, for_time: float | None = None, step: int = DEFAULT_STEP,
            digits: int = DEFAULT_DIGITS) -> str:
    """The current TOTP code (mainly for tests and display during MFA setup)."""
    counter = int((for_time if for_time is not None else time.time()) // step)
    return _hotp(secret, counter, digits)


def verify_totp(secret: str, code: str, for_time: float | None = None, step: int = DEFAULT_STEP,
                digits: int = DEFAULT_DIGITS, window: int = DEFAULT_WINDOW) -> bool:
    """Verify a code, tolerating +/- ``window`` steps of clock drift. Rejects malformed input safely."""
    if not code or not code.isdigit() or len(code) != digits:
        return False
    now = for_time if for_time is not None else time.time()
    counter = int(now // step)
    return any(
        hmac.compare_digest(_hotp(secret, counter + offset, digits), code)
        for offset in range(-window, window + 1)
    )


def provisioning_uri(secret: str, account_name: str, issuer: str = "RegexSOC") -> str:
    """An otpauth:// URI suitable for rendering as a QR code during MFA enrollment."""
    label = quote(f"{issuer}:{account_name}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"


def generate_backup_codes(count: int = 10, length: int = 10) -> list[str]:
    """One-time recovery codes for when the authenticator device is unavailable. Store only their hash."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no ambiguous 0/O/1/I
    return ["".join(secrets.choice(alphabet) for _ in range(length)) for _ in range(count)]
