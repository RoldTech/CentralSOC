"""A small in-process fixed-window rate limiter for endpoints that do not need database-backed lockout
(login lockout, which must survive restarts and work under a load balancer, uses the database instead;
see db.auth_service). This limiter is process-local: under multiple worker processes each gets its own
counters. For production multi-process deployments, back this with Redis (e.g. Flask-Limiter + Redis);
this implementation is a dependency-free default suitable for a single-process deployment or a demo.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class FixedWindowLimiter:
    """Allows at most ``limit`` calls per ``window_seconds`` for each key."""

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window_seconds: float, now: float | None = None) -> bool:
        now = now if now is not None else time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > window_seconds:
                hits.popleft()
            if len(hits) >= limit:
                return False
            hits.append(now)
            return True

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._hits.clear()
            else:
                self._hits.pop(key, None)
