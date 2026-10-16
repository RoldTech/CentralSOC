"""Open-redirect protection for post-login ``next`` targets."""

from __future__ import annotations

from urllib.parse import urlsplit


def safe_next(target: str | None) -> str | None:
    """Return ``target`` only if it is a plain same-site relative path; otherwise None."""
    if not target or len(target) > 2000:
        return None
    if any(ord(c) < 32 or ord(c) == 127 for c in target):  # browsers strip tabs/newlines: "/\t/evil.com"
        return None
    if not target.startswith("/") or target.startswith("//") or "\\" in target:
        return None
    parts = urlsplit(target)
    if parts.scheme or parts.netloc:
        return None
    return target
