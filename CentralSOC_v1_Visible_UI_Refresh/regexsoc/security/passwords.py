"""Password hashing.

Prefers Argon2id (argon2-cffi) when installed. Falls back to scrypt (hashlib, stdlib, memory-hard,
no extra dependency) so the application works without any extra install and so this module is fully
testable without argon2-cffi. Both are safe, salted, slow-by-design hashes; scrypt is not a "weaker
placeholder", it is a legitimate password hashing choice (OWASP-approved) used here as a dependency-free
default. Either hash is self-describing, so verification works regardless of which one created it, and
switching backends later is transparent to existing users (see ``needs_rehash``).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError

    _argon2 = PasswordHasher()
except ImportError:
    _argon2 = None

_SCRYPT_N, _SCRYPT_R, _SCRYPT_P, _SCRYPT_DKLEN, _SCRYPT_SALT_LEN = 2**14, 8, 1, 32, 16
MIN_LENGTH = 12
_COMMON_WEAK = {"password", "password123", "123456", "123456789", "qwerty", "letmein", "admin",
               "changeme", "welcome", "iloveyou", "monkey", "dragon"}


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _scrypt_hash(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P,
                          dklen=_SCRYPT_DKLEN)


def hash_password(password: str) -> str:
    """Hash a password. Uses Argon2id if available, otherwise scrypt."""
    if not password:
        raise ValueError("password must not be empty")
    if _argon2 is not None:
        return "argon2$" + _argon2.hash(password)
    salt = os.urandom(_SCRYPT_SALT_LEN)
    digest = _scrypt_hash(password, salt)
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Constant-time verification. Never raises on malformed input; just returns False."""
    if not password or not stored_hash:
        return False
    try:
        scheme, rest = stored_hash.split("$", 1)
    except ValueError:
        return False
    if scheme == "argon2":
        if _argon2 is None:
            return False  # cannot verify an argon2 hash without the library installed
        try:
            return _argon2.verify(rest, password)
        except VerifyMismatchError:
            return False
        except Exception:
            return False
    if scheme == "scrypt":
        try:
            n, r, p, salt_b64, hash_b64 = rest.split("$")
            digest = hashlib.scrypt(password.encode("utf-8"), salt=_unb64(salt_b64), n=int(n), r=int(r),
                                    p=int(p), dklen=len(_unb64(hash_b64)))
        except (ValueError, TypeError):
            return False
        return hmac.compare_digest(digest, _unb64(hash_b64))
    return False  # unknown scheme


def needs_rehash(stored_hash: str) -> bool:
    """True if the hash should be regenerated (wrong parameters, or Argon2 now available but not used)."""
    scheme, _, rest = stored_hash.partition("$")
    if scheme == "argon2":
        return _argon2 is not None and _argon2.check_needs_rehash(rest)
    if scheme == "scrypt":
        if _argon2 is not None:
            return True  # upgrade opportunistically once Argon2 is installed
        try:
            n, r, p = (int(x) for x in rest.split("$")[:3])
        except ValueError:
            return True
        return (n, r, p) != (_SCRYPT_N, _SCRYPT_R, _SCRYPT_P)
    return True


def validate_password_strength(password: str, username: str | None = None) -> list[str]:
    """Return a list of policy violations (empty list = acceptable). Applied at registration/change time."""
    problems = []
    if len(password) < MIN_LENGTH:
        problems.append(f"must be at least {MIN_LENGTH} characters")
    if password.isdigit():
        problems.append("must not be entirely numeric")
    if password.lower() in _COMMON_WEAK:
        problems.append("is a commonly used password")
    if username and password.lower() == username.lower():
        problems.append("must not match the username")
    return problems
