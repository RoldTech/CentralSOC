"""Log parsers. ``parse_line`` tries specific formats first and falls back to the generic parser."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Iterable

from regexsoc.config import MAX_LINE_LENGTH
from regexsoc.models import Event
from regexsoc.parsers import generic, syslog, web, windows


def parse_line(line: str, line_number: int = 0, year: int | None = None) -> Event | None:
    """Parse one raw log line into a normalized Event; blank lines and comments return None."""
    line = line.rstrip("\r\n")[:MAX_LINE_LENGTH]
    if not line.strip() or line.lstrip().startswith("#"):
        return None
    year = year or datetime.now(UTC).year
    return (
        windows.parse(line, line_number)
        or web.parse(line, line_number)
        or syslog.parse(line, year, line_number)
        or generic.parse(line, line_number)
    )


def parse_lines(lines: Iterable[str], year: int | None = None, start_id: int = 1) -> list[Event]:
    """Parse many lines, assigning sequential event IDs."""
    events: list[Event] = []
    next_id = start_id
    for number, line in enumerate(lines, start=1):
        event = parse_line(line, number, year)
        if event is not None:
            event.id = next_id
            next_id += 1
            events.append(event)
    return events
