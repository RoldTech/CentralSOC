"""Time-range filter for alerts/events/detections. Pure logic (no Flask/DB), so it is directly
testable. Returns naive UTC, matching this project's storage convention (see models.utcnow()).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

# Default is "all time", not a recent window: this project's own sample/demo data carries a fixed
# historical timestamp, so a recency-first default would show an empty dashboard out of the box.
DEFAULT_RANGE = ""

LABELS = (
    ("15m", "Last 15 minutes"),
    ("1h", "Last hour"),
    ("24h", "Last 24 hours"),
    ("7d", "Last 7 days"),
    ("30d", "Last 30 days"),
    ("", "All time"),
)
_DELTAS = {"15m": timedelta(minutes=15), "1h": timedelta(hours=1), "24h": timedelta(hours=24),
          "7d": timedelta(days=7), "30d": timedelta(days=30)}


def is_valid(range_key: str) -> bool:
    return range_key in _DELTAS or range_key == ""


def since(range_key: str, now: datetime | None = None) -> datetime | None:
    """The earliest timestamp to include for this range key, or None for "all time"/unknown keys.
    ``now`` is only for tests; real callers omit it and get the current naive-UTC time."""
    delta = _DELTAS.get(range_key)
    if delta is None:
        return None
    now = now if now is not None else datetime.now(UTC).replace(tzinfo=None)
    return now - delta
