"""Time-window correlation rules (brute force, spraying, scans, error bursts...)."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import timedelta

from regexsoc.detectors.base import Detection
from regexsoc.models import Event
from regexsoc.rules.definitions import Rule

MAX_EVIDENCE = 5


def _best_window(events: list[Event], window: timedelta) -> tuple[int, list[Event]]:
    """Slide a window over time-sorted events.

    Returns (max_events_in_any_window, those_events).
    """
    left, best = 0, events[:0]
    for right, event in enumerate(events):
        while event.timestamp - events[left].timestamp > window:
            left += 1
        if right - left + 1 > len(best):
            best = events[left : right + 1]
    return len(best), best


def _widest_distinct(events: list[Event], window: timedelta, key, threshold: int) -> list[Event]:
    """Widest time window containing at least ``threshold`` distinct ``key`` values (or [])."""
    left, best = 0, events[:0]
    counts: Counter = Counter()
    for right, event in enumerate(events):
        counts[key(event)] += 1
        while event.timestamp - events[left].timestamp > window:
            k = key(events[left])
            counts[k] -= 1
            if counts[k] == 0:
                del counts[k]
            left += 1
        if len(counts) >= threshold and right - left + 1 > len(best):
            best = events[left : right + 1]
    return best


def _select(events: list[Event], patterns: list[re.Pattern[str]]) -> dict[str, list[Event]]:
    """Group timestamped events whose raw line matches any pattern by source IP."""
    groups: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        if event.source_ip and event.timestamp and any(p.search(event.raw_log) for p in patterns):
            groups[event.source_ip].append(event)
    for items in groups.values():
        items.sort(key=lambda e: e.timestamp)
    return groups


def _detection(rule: Rule, ip: str, window_events: list[Event], reason: str, details: dict) -> Detection:
    users = sorted({e.username for e in window_events if e.username})
    return Detection.from_rule(
        rule, reason=reason, source_ip=ip,
        username=users[0] if len(users) == 1 else None,
        event_type=window_events[0].event_type, timestamp=window_events[0].timestamp,
        event_ids=[e.id for e in window_events],
        evidence=[e.raw_log for e in window_events[:MAX_EVIDENCE]],
        details=details | {"users": users[:20]},
    )


def _threshold(rule: Rule, events: list[Event]) -> list[Detection]:
    window = timedelta(seconds=rule.params["window_seconds"])
    out = []
    for ip, items in _select(events, list(rule.regexes)).items():
        count, win = _best_window(items, window)
        if count >= rule.params["threshold"]:
            reason = (f"{count} matching events from {ip} within "
                      f"{rule.params['window_seconds']}s (threshold {rule.params['threshold']}).")
            out.append(_detection(rule, ip, win, reason, {"count": count, "window_seconds": rule.params["window_seconds"]}))
    return out


def _distinct(rule: Rule, events: list[Event]) -> list[Detection]:
    window = timedelta(seconds=rule.params["window_seconds"])
    field_name = rule.params["field"]
    out = []
    for ip, items in _select(events, list(rule.regexes)).items():
        items = [e for e in items if getattr(e, field_name) is not None]
        if not items:
            continue
        win = _widest_distinct(items, window, lambda e: getattr(e, field_name), rule.params["threshold"])
        if not win:
            continue
        per_value = Counter(getattr(e, field_name) for e in win)
        count, cap = len(per_value), rule.params.get("max_per_value")
        if cap is not None and max(per_value.values()) > cap:
            continue  # heavy per-value repetition is brute force, not spraying
        reason = (f"{ip} touched {count} distinct {field_name} values within "
                  f"{rule.params['window_seconds']}s (threshold {rule.params['threshold']}).")
        out.append(_detection(rule, ip, win, reason, {"distinct": count, "field": field_name}))
    return out


def _success_after_failures(rule: Rule, events: list[Event]) -> list[Detection]:
    window = timedelta(seconds=rule.params["window_seconds"])
    min_failures = rule.params["min_failures"]
    fail_rx = [re.compile(p) for p in rule.params["failure_patterns"]]
    failures = _select(events, fail_rx)
    out = []
    for ip, successes in _select(events, list(rule.regexes)).items():
        fails = failures.get(ip, [])
        for success in successes:
            # Correlate to the same account when both event identities are known.
            # An unrelated account failing from the same NAT/source IP must not
            # be used as evidence of compromise of the successful account.
            prior = [
                f for f in fails
                if success.timestamp - window <= f.timestamp <= success.timestamp
                and (not success.username or not f.username or f.username == success.username)
            ]
            if len(prior) >= min_failures:
                reason = (f"Successful login from {ip} after {len(prior)} failures "
                          f"within {rule.params['window_seconds']}s.")
                out.append(_detection(rule, ip, prior[-(MAX_EVIDENCE - 1):] + [success], reason,
                                      {"failures": len(prior)}))
                out[-1].username = success.username
                out[-1].event_type = success.event_type
                out[-1].timestamp = success.timestamp
                break  # one detection per IP is enough for triage
    return out


_KINDS = {"threshold": _threshold, "distinct": _distinct, "success_after_failures": _success_after_failures}


def correlate(events: list[Event], rules: list[Rule]) -> list[Detection]:
    """Run every enabled correlation rule over a list of events."""
    detections: list[Detection] = []
    for rule in rules:
        if rule.enabled and rule.target == "correlation":
            detections.extend(_KINDS[rule.params["kind"]](rule, events))
    return detections
