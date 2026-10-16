"""Runtime configuration, read from environment variables (never hardcoded secrets)."""

from __future__ import annotations

import os
from pathlib import Path

try:  # python-dotenv is optional; environment variables work without it
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass


def rule_state_path() -> Path:
    """Where enable/disable overrides for rules are persisted."""
    return Path(os.environ.get("REGEXSOC_RULE_STATE", "instance/rule_state.json"))


def max_input_bytes() -> int:
    """Upper bound on the size of a log file the CLI will read (default 50 MB)."""
    return int(os.environ.get("REGEXSOC_MAX_INPUT_BYTES", 50 * 1024 * 1024))


MAX_LINE_LENGTH = 8192  # longer lines are truncated to bound regex work (ReDoS hardening)


def database_url() -> str:
    """SQLAlchemy URL. SQLite by default; set DATABASE_URL for PostgreSQL etc."""
    return os.environ.get("DATABASE_URL", "sqlite:///instance/regexsoc.db")


def upload_dir() -> Path:
    """Where uploaded/ingested log copies are stored (must be outside any web-served directory)."""
    return Path(os.environ.get("REGEXSOC_UPLOAD_DIR", "instance/uploads"))


def integrity_key() -> bytes | None:
    """Optional secret that turns the event hash chain into an HMAC chain (harder to forge)."""
    key = os.environ.get("REGEXSOC_INTEGRITY_KEY")
    return key.encode("utf-8") if key else None


def is_development() -> bool:
    return os.environ.get("REGEXSOC_ENV", "production").lower() == "development"


def secret_key() -> str:
    """The Flask session/CSRF signing key. Required in production; auto-generated (with a warning)
    in development so a fresh checkout can run without extra setup."""
    key = os.environ.get("REGEXSOC_SECRET_KEY")
    if key:
        return key
    if is_development():
        import secrets
        import warnings

        warnings.warn(
            "REGEXSOC_SECRET_KEY is not set; using a random development-only key. Sessions will not "
            "survive a restart and this is NOT safe for production.", stacklevel=2,
        )
        return secrets.token_hex(32)
    raise RuntimeError(
        "REGEXSOC_SECRET_KEY is not set. Generate one with: python -c \"import secrets; "
        "print(secrets.token_hex(32))\" and put it in your .env file, or set REGEXSOC_ENV=development "
        "for local testing only."
    )


def session_lifetime_minutes() -> int:
    return int(os.environ.get("REGEXSOC_SESSION_MINUTES", 30))


def lockout_policy():
    from regexsoc.security.lockout import LockoutPolicy

    return LockoutPolicy(
        max_failures=int(os.environ.get("REGEXSOC_LOCKOUT_MAX_FAILURES", 5)),
        window_minutes=int(os.environ.get("REGEXSOC_LOCKOUT_WINDOW_MINUTES", 15)),
        cooldown_minutes=int(os.environ.get("REGEXSOC_LOCKOUT_COOLDOWN_MINUTES", 15)),
    )


ALLOWED_UPLOAD_EXTENSIONS = (".log", ".txt", ".csv", ".json", ".jsonl")

# Raw RFC 5322 / .eml text only. Proprietary binary mail formats (Outlook .msg, etc.) are NOT
# supported — Python's email module cannot parse them and would silently produce garbage.
ALLOWED_EMAIL_EXTENSIONS = (".eml", ".txt")


def max_upload_bytes() -> int:
    return max_input_bytes()
