"""Account lockout policy: pure logic over a list of recent attempts (no database dependency, so it
is directly unit-testable; regexsoc.db.auth_service supplies the attempts from LoginAttempt rows).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass(frozen=True)
class LockoutPolicy:
    max_failures: int = 5
    window_minutes: int = 15
    cooldown_minutes: int = 15


DEFAULT_POLICY = LockoutPolicy()


def is_locked(attempts: list[tuple[datetime, bool]], now: datetime, policy: LockoutPolicy = DEFAULT_POLICY) -> bool:
    """``attempts`` is a list of (timestamp, success), newest first. Locked if the most recent
    ``max_failures`` attempts within the window are all failures and the cooldown has not elapsed."""
    window_start = now - timedelta(minutes=policy.window_minutes)
    recent = [a for a in attempts if a[0] >= window_start]
    consecutive_failures = 0
    for _, success in recent:
        if success:
            break
        consecutive_failures += 1
    if consecutive_failures < policy.max_failures:
        return False
    last_failure_time = recent[consecutive_failures - 1][0]
    return now - last_failure_time < timedelta(minutes=policy.cooldown_minutes)


def seconds_remaining(attempts: list[tuple[datetime, bool]], now: datetime,
                      policy: LockoutPolicy = DEFAULT_POLICY) -> int:
    """Seconds left in the lockout, 0 if not locked."""
    if not is_locked(attempts, now, policy):
        return 0
    last_failure_time = next(t for t, success in attempts if not success)
    remaining = timedelta(minutes=policy.cooldown_minutes) - (now - last_failure_time)
    return max(0, int(remaining.total_seconds()))
