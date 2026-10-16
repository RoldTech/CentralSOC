"""Real-time monitoring: follow a log file read-only and alert as events arrive."""

from __future__ import annotations

import os
import time
from collections import deque
from datetime import timedelta
from typing import Callable, Iterator

from regexsoc.models import Event
from regexsoc.parsers import parse_line
from regexsoc.services.alerts import Alert
from regexsoc.services.analyzer import Analyzer


class StreamAnalyzer:
    """Incremental analyzer: keeps a rolling buffer so correlation rules work on live data."""

    def __init__(self, analyzer: Analyzer, buffer_seconds: int = 900, cooldown_seconds: int = 300) -> None:
        self.analyzer = analyzer
        self.buffer: deque[Event] = deque()
        self.buffer_seconds = buffer_seconds
        self.cooldown = timedelta(seconds=cooldown_seconds)
        self._last_fired: dict[tuple, object] = {}
        self._next_id = 1

    def feed(self, line: str) -> list[Alert]:
        """Process one new line and return any *new* alerts it caused."""
        event = parse_line(line, year=self.analyzer.default_year)
        if event is None:
            return []
        event.id, self._next_id = self._next_id, self._next_id + 1
        self.buffer.append(event)
        if event.timestamp:
            horizon = event.timestamp - timedelta(seconds=self.buffer_seconds)
            while self.buffer and self.buffer[0].timestamp and self.buffer[0].timestamp < horizon:
                self.buffer.popleft()
        result = self.analyzer.analyze_events(list(self.buffer))
        fresh: list[Alert] = []
        for alert in result.alerts:
            key = (alert.rule_id, alert.source_ip, alert.username)
            last = self._last_fired.get(key)
            stamp = alert.timestamp or event.timestamp
            if last is not None and stamp is not None and stamp - last < self.cooldown:
                continue
            self._last_fired[key] = stamp
            fresh.append(alert)
        return fresh


def follow(path: str, poll_interval: float = 1.0, from_start: bool = False,
           should_stop: Callable[[], bool] = lambda: False) -> Iterator[str]:
    """Yield new lines appended to ``path``. The file is opened read-only and never modified.

    Handles truncation and rotation by re-opening when the inode changes or the file shrinks.
    """
    handle = open(path, "r", encoding="utf-8", errors="replace")
    try:
        inode = os.fstat(handle.fileno()).st_ino
        if not from_start:
            handle.seek(0, os.SEEK_END)
        while not should_stop():
            line = handle.readline()
            if line:
                yield line
                continue
            time.sleep(poll_interval)
            try:
                stat = os.stat(path)
            except FileNotFoundError:
                continue
            if stat.st_ino != inode or stat.st_size < handle.tell():
                handle.close()
                handle = open(path, "r", encoding="utf-8", errors="replace")
                inode = os.fstat(handle.fileno()).st_ino
    finally:
        handle.close()
