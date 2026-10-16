"""IP address helpers built on the stdlib ``ipaddress`` module (no regex guesswork)."""

from __future__ import annotations

import ipaddress


def normalize_ip(value: str | None) -> str | None:
    """Return the canonical form of an IPv4/IPv6 address, or None if invalid."""
    if not value:
        return None
    candidate = value.strip().strip("[]").split("%", 1)[0]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def is_private(value: str) -> bool:
    """True for private, loopback, link-local and reserved addresses."""
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
