"""Audit-log helpers: action names, secret redaction and log-injection protection."""

from __future__ import annotations

import json
import re
from typing import Any, Mapping


class AuditAction:
    LOGIN = "LOGIN"
    LOGIN_FAILED = "LOGIN_FAILED"
    LOGOUT = "LOGOUT"
    FILE_UPLOAD = "FILE_UPLOAD"
    INTEGRITY_CHECK = "INTEGRITY_CHECK"
    RULE_MODIFIED = "RULE_MODIFIED"
    ALERT_STATUS_CHANGED = "ALERT_STATUS_CHANGED"
    ALERT_NOTE_ADDED = "ALERT_NOTE_ADDED"
    ALERT_ASSIGNED = "ALERT_ASSIGNED"
    ALERT_ACKNOWLEDGED = "ALERT_ACKNOWLEDGED"
    ALERT_VERDICT_SET = "ALERT_VERDICT_SET"
    ALERT_QUEUE_EXPORTED = "ALERT_QUEUE_EXPORTED"
    REPORT_EXPORTED = "REPORT_EXPORTED"
    INCIDENTS_EXPORTED = "INCIDENTS_EXPORTED"
    INCIDENT_CREATED = "INCIDENT_CREATED"
    INCIDENT_UPDATED = "INCIDENT_UPDATED"
    INCIDENT_ALERT_LINKED = "INCIDENT_ALERT_LINKED"
    INCIDENT_NOTE_ADDED = "INCIDENT_NOTE_ADDED"
    PLAYBOOK_SELECTED = "PLAYBOOK_SELECTED"
    PLAYBOOK_STEP_COMPLETED = "PLAYBOOK_STEP_COMPLETED"
    USER_CREATED = "USER_CREATED"
    USER_ROLE_CHANGED = "USER_ROLE_CHANGED"
    CONFIG_CHANGED = "CONFIG_CHANGED"
    USER_STATUS_CHANGED = "USER_STATUS_CHANGED"
    PASSWORD_CHANGED = "PASSWORD_CHANGED"
    MFA_ENABLED = "MFA_ENABLED"
    MFA_FAILED = "MFA_FAILED"
    MFA_RESET = "MFA_RESET"
    EMAIL_ANALYZED = "EMAIL_ANALYZED"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
    ACCOUNT_UNLOCKED = "ACCOUNT_UNLOCKED"
    ACCESS_DENIED = "ACCESS_DENIED"


RESULTS = ("SUCCESS", "FAILURE", "DENIED")
REDACTED = "[REDACTED]"
SENSITIVE_KEY_PARTS = ("password", "passwd", "secret", "token", "session", "cookie", "authorization",
                       "api_key", "apikey", "totp", "otp", "mfa", "csrf", "private_key", "credential")

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_INLINE_SECRET = re.compile(
    r"(?i)\b(pass(?:word|wd)?|secret|token|api[_-]?key|authorization|cookie|session(?:id)?|otp|totp)\b"
    r"(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|(?:Bearer\s+|Basic\s+)?\S+)"
)


def _truncate(text: str, max_len: int) -> str:
    return text if len(text) <= max_len else text[: max_len - 1] + "\u2026"


def _scrub(text: str) -> str:
    """Strip control characters (blocks log forging via newlines) and redact inline secrets."""
    text = _CONTROL.sub(" ", text)
    return _INLINE_SECRET.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text)


def clean_text(value: Any, max_len: int = 500) -> str:
    """Make text safe for the audit log: scrub control chars and inline secrets, then truncate."""
    return _truncate(_scrub(str(value)), max_len)


def redact(value: Any) -> Any:
    """Recursively replace values whose key looks sensitive."""
    if isinstance(value, Mapping):
        return {k: (REDACTED if any(p in str(k).lower() for p in SENSITIVE_KEY_PARTS) else redact(v))
                for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return _scrub(value)  # inline secrets inside string values
    return value


def format_detail(detail: Any, max_len: int = 1000) -> str | None:
    """Render an audit ``detail`` (string or mapping) into a sanitized string."""
    if detail is None:
        return None
    if isinstance(detail, str):
        return clean_text(detail, max_len)
    # Redaction happens on the values *before* serialising, so the JSON structure is never corrupted.
    return _truncate(json.dumps(redact(detail), sort_keys=True, default=str), max_len)
