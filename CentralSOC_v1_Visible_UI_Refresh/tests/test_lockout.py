from datetime import datetime, timedelta

from regexsoc.security.lockout import DEFAULT_POLICY, LockoutPolicy, is_locked, seconds_remaining

NOW = datetime(2024, 3, 10, 12, 0, 0)


def fails(n, start_minutes_ago=1, step_seconds=10):
    return [(NOW - timedelta(minutes=start_minutes_ago) + timedelta(seconds=i * step_seconds), False)
            for i in range(n)][::-1]


def test_not_locked_below_threshold():
    assert not is_locked(fails(4), NOW)


def test_locked_at_threshold():
    assert is_locked(fails(5), NOW)


def test_success_resets_the_streak():
    attempts = fails(4) + [(NOW - timedelta(minutes=2), True)] + fails(3, start_minutes_ago=5)
    assert not is_locked(attempts, NOW)


def test_old_failures_outside_window_do_not_count():
    old_failures = [(NOW - timedelta(minutes=30), False)] * 5
    assert not is_locked(old_failures, NOW)


def test_lock_expires_after_cooldown():
    attempts = fails(5, start_minutes_ago=20)  # failures are 20 min old
    policy = LockoutPolicy(max_failures=5, window_minutes=60, cooldown_minutes=15)
    assert not is_locked(attempts, NOW, policy)  # cooldown (15 min) has passed


def test_seconds_remaining_counts_down():
    attempts = fails(5, start_minutes_ago=1)
    remaining = seconds_remaining(attempts, NOW, DEFAULT_POLICY)
    assert 0 < remaining <= DEFAULT_POLICY.cooldown_minutes * 60


def test_seconds_remaining_zero_when_not_locked():
    assert seconds_remaining(fails(1), NOW) == 0


def test_no_attempts_is_not_locked():
    assert not is_locked([], NOW)


def test_custom_policy_stricter_threshold():
    policy = LockoutPolicy(max_failures=3, window_minutes=10, cooldown_minutes=5)
    assert is_locked(fails(3), NOW, policy)
    assert not is_locked(fails(2), NOW, policy)
