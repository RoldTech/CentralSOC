"""Timestamp parsing. Every timestamp is normalized to timezone-aware UTC."""

from __future__ import annotations

from datetime import UTC, datetime


def parse_syslog(ts: str, year: int) -> datetime | None:
    """Parse ``Mar 10 10:15:01`` (syslog has no year, so the caller supplies one)."""
    try:
        return datetime.strptime(f"{year} {ts}", "%Y %b %d %H:%M:%S").replace(tzinfo=UTC)
    except ValueError:
        return None


def parse_apache(ts: str) -> datetime | None:
    """Parse ``10/Mar/2024:10:15:01 +0000``."""
    try:
        return datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z").astimezone(UTC)
    except ValueError:
        return None


def parse_iso(ts: str) -> datetime | None:
    """Parse ISO-8601-like timestamps; naive values are assumed to be UTC."""
    try:
        parsed = datetime.fromisoformat(ts.strip().replace(" ", "T", 1))
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
