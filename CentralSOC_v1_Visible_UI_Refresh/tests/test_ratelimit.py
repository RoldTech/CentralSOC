from regexsoc.security.ratelimit import FixedWindowLimiter


def test_allows_up_to_limit_then_blocks():
    limiter = FixedWindowLimiter()
    now = 1000.0
    assert all(limiter.allow("k", 3, 60, now=now) for _ in range(3))
    assert limiter.allow("k", 3, 60, now=now) is False


def test_window_resets_over_time():
    limiter = FixedWindowLimiter()
    for _ in range(5):
        limiter.allow("k", 5, 60, now=1000.0)
    assert limiter.allow("k", 5, 60, now=1000.0) is False
    assert limiter.allow("k", 5, 60, now=1062.0) is True  # old hits have aged out


def test_keys_are_independent():
    limiter = FixedWindowLimiter()
    for _ in range(5):
        limiter.allow("a", 5, 60, now=1000.0)
    assert limiter.allow("a", 5, 60, now=1000.0) is False
    assert limiter.allow("b", 5, 60, now=1000.0) is True


def test_reset_single_key_and_all():
    limiter = FixedWindowLimiter()
    limiter.allow("a", 1, 60, now=1000.0)
    limiter.allow("b", 1, 60, now=1000.0)
    limiter.reset("a")
    assert limiter.allow("a", 1, 60, now=1000.0) is True
    assert limiter.allow("b", 1, 60, now=1000.0) is False
    limiter.reset()
    assert limiter.allow("b", 1, 60, now=1000.0) is True
