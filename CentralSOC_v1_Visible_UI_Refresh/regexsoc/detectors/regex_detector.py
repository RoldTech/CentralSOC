"""Per-event regex detection."""

from __future__ import annotations

from regexsoc.detectors.base import Detection
from regexsoc.models import Event
from regexsoc.rules.definitions import Rule

EVENT_TARGETS = {"raw", "request", "user_agent"}


def _text_for(rule: Rule, event: Event) -> str | None:
    if rule.target == "raw":
        return event.raw_log
    if rule.target == "request":
        return event.request_target if event.is_web else None
    if rule.target == "user_agent":
        return event.user_agent
    return None


def detect_event(event: Event, rules: list[Rule]) -> list[Detection]:
    """Run every enabled per-event rule against one event."""
    found: list[Detection] = []
    for rule in rules:
        if not rule.enabled or rule.target not in EVENT_TARGETS:
            continue
        text = _text_for(rule, event)
        if not text:
            continue
        match = rule.search(text)
        if match:
            snippet = match.group(0)[:60]
            found.append(
                Detection.from_rule(
                    rule,
                    reason=f"Pattern matched '{snippet}' in {rule.target.replace('_', ' ')}.",
                    source_ip=event.source_ip, username=event.username, event_type=event.event_type,
                    timestamp=event.timestamp, event_ids=[event.id], evidence=[event.raw_log],
                    details={"matched": snippet},
                )
            )
    return found
