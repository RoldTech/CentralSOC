from datetime import UTC, datetime, timedelta

import pytest

from regexsoc.web.timerange import DEFAULT_RANGE, LABELS, is_valid, since

NOW = datetime(2024, 3, 10, 12, 0, 0)


@pytest.mark.parametrize("key,expected_delta", [
    ("15m", timedelta(minutes=15)), ("1h", timedelta(hours=1)), ("24h", timedelta(hours=24)),
    ("7d", timedelta(days=7)), ("30d", timedelta(days=30)),
])
def test_since_matches_expected_delta(key, expected_delta):
    assert since(key, NOW) == NOW - expected_delta


def test_empty_key_means_all_time():
    assert since("", NOW) is None


def test_unknown_key_means_all_time_not_an_error():
    assert since("bogus", NOW) is None


def test_is_valid():
    for key, _label in LABELS:
        assert is_valid(key)
    assert not is_valid("6 months")


def test_labels_cover_documented_ranges():
    keys = [k for k, _ in LABELS]
    assert keys == ["15m", "1h", "24h", "7d", "30d", ""]


def test_default_range_is_all_time():
    # Deliberate: this project's own sample/demo data has a fixed historical timestamp, so
    # defaulting to a recent window would show an empty dashboard out of the box.
    assert DEFAULT_RANGE == "" and is_valid(DEFAULT_RANGE)


def test_since_without_explicit_now_uses_real_clock():
    before = datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=1)
    result = since("1h")
    after = datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=1)
    assert result is not None and before <= result <= after
