"""Bounded, validated triage filters. This module is independent of Flask."""
from __future__ import annotations
from sqlalchemy import select
from regexsoc.db.models import Alert, ALERT_STATUSES
from regexsoc.web.timerange import DEFAULT_RANGE, is_valid

SEVERITIES = frozenset(("CRITICAL", "HIGH", "MEDIUM", "LOW"))
SORT_MODES = frozenset(("risk", "newest", "oldest"))


def normalize_alert_filters(args):
    """Reject unknown enumeration values; bound all free-text inputs."""
    severity = str(args.get("severity", "")).upper()
    status = str(args.get("status", ""))
    interval = str(args.get("time_range", DEFAULT_RANGE))
    ordering = str(args.get("sort", "risk"))
    return {
        "severity": severity if severity in SEVERITIES else "",
        "status": status if status in ALERT_STATUSES else "",
        "source_ip": str(args.get("source_ip", "")).strip()[:45],
        "username": str(args.get("username", "")).strip()[:255],
        "rule_id": str(args.get("rule_id", ""))[:20],
        "time_range": interval if is_valid(interval) else DEFAULT_RANGE,
        "sort": ordering if ordering in SORT_MODES else "risk",
        "ownership": str(args.get("ownership", "")) if args.get("ownership", "") in ("", "mine", "unassigned") else "",
    }


def build_alert_queue(filters, cutoff=None, current_username=None):
    statement = select(Alert)
    for key, column in (("severity", Alert.severity), ("status", Alert.status),
                        ("source_ip", Alert.source_ip), ("rule_id", Alert.rule_id),
                        ("username", Alert.username)):
        if filters.get(key):
            statement = statement.where(column == filters[key])
    if filters.get("ownership") == "unassigned":
        statement = statement.where(Alert.assigned_to.is_(None))
    elif filters.get("ownership") == "mine":
        statement = statement.where(Alert.assigned_to == current_username) if current_username else statement.where(False)
    if cutoff is not None:
        statement = statement.where(Alert.timestamp >= cutoff)
    return statement
