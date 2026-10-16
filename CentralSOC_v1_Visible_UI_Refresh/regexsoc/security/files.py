"""Filename sanitization. (Full upload validation arrives with the web app in Phase 3.)"""

from __future__ import annotations

import re

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")


def sanitize_filename(name: str | None, max_len: int = 120, default: str = "upload.log") -> str:
    """Reduce a user-supplied filename to a harmless display name.

    Strips directory components (both / and \\), replaces unexpected characters and removes leading dots.
    The result is for display only; stored files always get random server-side names.
    """
    base = re.split(r"[\\/]", name or "")[-1]
    base = _UNSAFE.sub("_", base).lstrip(".")[:max_len]
    return base or default
