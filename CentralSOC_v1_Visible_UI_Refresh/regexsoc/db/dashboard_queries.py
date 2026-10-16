"""Read-only query helpers backing the dashboard. Every query is parameterized through the ORM."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from regexsoc.db import models
from regexsoc.models import EventType
from regexsoc.web.search import SearchQuery

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
RESULTS_PER_SEARCH_SECTION = 25


def overview_stats(session: Session) -> dict:
    """Everything the overview page's cards and panels need, in one place."""
    alert_counts = dict(session.execute(select(models.Alert.severity, func.count()).group_by(models.Alert.severity)).all())
    event_type_counts = dict(session.execute(select(models.Event.event_type, func.count()).group_by(models.Event.event_type)).all())
    category_counts = dict(session.execute(select(models.Detection.category, func.count()).group_by(models.Detection.category)).all())
    top_ips = session.execute(
        select(models.Event.source_ip, func.count().label("n"))
        .where(models.Event.source_ip.is_not(None))
        .group_by(models.Event.source_ip).order_by(func.count().desc()).limit(8)
    ).all()
    return {
        "total_events": session.scalar(select(func.count()).select_from(models.Event)) or 0,
        "total_log_files": session.scalar(select(func.count()).select_from(models.LogFile)) or 0,
        "total_iocs": session.scalar(select(func.count()).select_from(models.IOC)) or 0,
        "alert_counts": {s: alert_counts.get(s, 0) for s in SEVERITIES},
        "failed_logins": event_type_counts.get(EventType.FAILED_LOGIN, 0),
        "successful_logins": event_type_counts.get(EventType.LOGIN_SUCCESS, 0),
        "top_source_ips": [(ip, n) for ip, n in top_ips],
        "detection_categories": sorted(category_counts.items(), key=lambda kv: -kv[1]),
    }


def analytics_overview(session: Session, days: int | None = 7, now: datetime | None = None) -> dict:
    """Bounded, database-backed UTC daily counts; no synthetic or client-provided SQL.

    The time range applies to all charts. Missing timestamps are omitted rather than
    assigned a misleading ingestion time. func.date works on SQLite and PostgreSQL.
    """
    if days not in (7, 30, None):
        raise ValueError("Unsupported dashboard window")
    now = now or datetime.now(timezone.utc)
    today = now.date()
    if days is None:
        # All-time view uses monthly buckets to keep multi-year histories readable.
        # Find the boundaries from actual persisted event/alert timestamps.
        minima = [session.scalar(select(func.min(model.timestamp))) for model in (models.Event, models.Alert)]
        maxima = [session.scalar(select(func.max(model.timestamp))) for model in (models.Event, models.Alert)]
        first = min((stamp for stamp in minima if stamp is not None), default=None)
        last = max((stamp for stamp in maxima if stamp is not None), default=None)
        first_month = (first.year, first.month) if first else (today.year, today.month)
        last_month = (last.year, last.month) if last else first_month
        def monthly(model):
            year, month = func.extract("year", model.timestamp), func.extract("month", model.timestamp)
            rows = session.execute(select(year, month, func.count()).where(model.timestamp.is_not(None))
                                   .group_by(year, month)).all()
            return {f"{int(y):04d}-{int(m):02d}": count for y, m, count in rows}
        events, alerts = monthly(models.Event), monthly(models.Alert)
        labels = []
        y, m = first_month
        while (y, m) <= last_month:
            labels.append(f"{y:04d}-{m:02d}")
            y, m = (y + 1, 1) if m == 12 else (y, m + 1)
        conditions = lambda model: (model.timestamp.is_not(None),)
        start_label, end_label = labels[0], labels[-1]
        granularity = "Monthly"
    else:
        first_day = today - timedelta(days=days - 1)
        # Stored SQLAlchemy timestamps are UTC-naive in the current application schema.
        cutoff = datetime.combine(first_day, datetime.min.time())
        upper = datetime.combine(today + timedelta(days=1), datetime.min.time())
        def daily(model):
            day = func.date(model.timestamp)
            rows = session.execute(select(day, func.count()).where(
                model.timestamp >= cutoff, model.timestamp < upper).group_by(day)).all()
            return {str(day): count for day, count in rows}
        events, alerts = daily(models.Event), daily(models.Alert)
        labels = [(first_day + timedelta(days=i)).isoformat() for i in range(days)]
        conditions = lambda model: (model.timestamp >= cutoff, model.timestamp < upper)
        start_label, end_label = first_day.isoformat(), today.isoformat()
        granularity = "Daily"
    alert_severity = dict(session.execute(
        select(models.Alert.severity, func.count())
        .where(*conditions(models.Alert))
        .group_by(models.Alert.severity)
    ).all())
    categories = session.execute(
        select(models.Detection.category, func.count())
        .where(*conditions(models.Detection))
        .group_by(models.Detection.category).order_by(func.count().desc()).limit(6)
    ).all()
    auth = session.execute(
        select(models.Event.event_type, func.count())
        .where(*conditions(models.Event),
               models.Event.event_type.in_((EventType.FAILED_LOGIN, EventType.LOGIN_SUCCESS)))
        .group_by(models.Event.event_type)
    ).all()
    auth_counts = dict(auth)
    return {
        "days": days,
        "start": start_label,
        "end": end_label,
        "granularity": granularity,
        "timeline": [{"date": label, "events": events.get(label, 0), "alerts": alerts.get(label, 0)} for label in labels],
        "severity": [{"name": name.title(), "count": alert_severity.get(name, 0)} for name in SEVERITIES],
        "categories": [{"name": name or "Uncategorized", "count": count} for name, count in categories],
        "authentication": [
            {"name": "Failed", "count": auth_counts.get(EventType.FAILED_LOGIN, 0)},
            {"name": "Successful", "count": auth_counts.get(EventType.LOGIN_SUCCESS, 0)},
        ],
    }


def analyst_workload(session: Session, *, limit: int = 12) -> dict:
    """Read-only alert ownership snapshot; not a measure of analyst performance.

    Active means New or Investigating. Historical/closed alerts are excluded.
    No SLA or time-to-response estimates are inferred from incomplete timestamps.
    """
    active = ("New", "Investigating")
    counts = dict(session.execute(
        select(models.Alert.status, func.count())
        .where(models.Alert.status.in_(active))
        .group_by(models.Alert.status)
    ).all())
    unassigned = session.scalar(select(func.count()).select_from(models.Alert).where(
        models.Alert.status.in_(active), models.Alert.assigned_to.is_(None)
    )) or 0
    assignments = session.execute(
        select(models.Alert.assigned_to, func.count(), func.max(models.Alert.risk_score))
        .where(models.Alert.status.in_(active), models.Alert.assigned_to.is_not(None))
        .group_by(models.Alert.assigned_to)
        .order_by(func.count().desc(), models.Alert.assigned_to.asc())
        .limit(max(1, min(int(limit), 50)))
    ).all()
    return {
        "active": sum(counts.values()),
        "new": counts.get("New", 0),
        "investigating": counts.get("Investigating", 0),
        "unassigned": unassigned,
        "analysts": [
            {"username": username, "active_count": count, "highest_risk": high}
            for username, count, high in assignments
        ],
    }


def incident_overview(session: Session) -> dict:
    """Database-backed incident totals and recent cases; no estimated or demo data."""
    by_status = dict(session.execute(
        select(models.Incident.status, func.count())
        .group_by(models.Incident.status)
    ).all())
    latest = list(session.scalars(
        select(models.Incident)
        .order_by(models.Incident.updated_at.desc(), models.Incident.id.desc())
        .limit(5)
    ))
    return {
        "total": sum(by_status.values()),
        "by_status": {status: by_status.get(status, 0) for status in models.INCIDENT_STATUSES},
        "active": sum(by_status.get(status, 0) for status in ("Open", "Investigating", "Contained")),
        "recent": latest,
    }


def detection_overview(session: Session) -> dict:
    """Aggregate rule match count and distinct rules using persisted detections."""
    return {
        "matches": session.scalar(select(func.count()).select_from(models.Detection)) or 0,
        "rules_fired": session.scalar(select(func.count(func.distinct(models.Detection.rule_id)))) or 0,
    }


def log_file_summary(session: Session, log_file_id: int) -> dict:
    """The 'Analysis Summary' card row for one ingested file."""
    from regexsoc.models import EventType

    events_q = select(models.Event).where(models.Event.log_file_id == log_file_id)
    type_counts = dict(session.execute(
        select(models.Event.event_type, func.count()).where(models.Event.log_file_id == log_file_id)
        .group_by(models.Event.event_type)
    ).all())
    total = sum(type_counts.values())
    http_errors = session.scalar(
        select(func.count()).select_from(events_q.where(models.Event.http_status >= 400).subquery())
    ) or 0
    suspicious = session.scalar(
        select(func.count()).select_from(events_q.where(models.Event.severity != "LOW").subquery())
    ) or 0
    ioc_count = session.scalar(
        select(func.count()).select_from(select(models.IOC).where(models.IOC.log_file_id == log_file_id).subquery())
    ) or 0
    return {"total_events": total, "failed_logins": type_counts.get(EventType.FAILED_LOGIN, 0),
           "successful_logins": type_counts.get(EventType.LOGIN_SUCCESS, 0), "http_errors": http_errors,
           "suspicious_events": suspicious, "iocs_extracted": ioc_count}


def log_file_events(session: Session, log_file_id: int, page: int = 1, page_size: int = 25) -> tuple[list[models.Event], int]:
    query = select(models.Event).where(models.Event.log_file_id == log_file_id)
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = session.scalars(query.order_by(models.Event.seq).offset((page - 1) * page_size).limit(page_size)).all()
    return list(rows), total


def recent_alerts(session: Session, limit: int = 10) -> list[models.Alert]:
    return list(session.scalars(select(models.Alert).order_by(models.Alert.id.desc()).limit(limit)))


def alert_timeline(session: Session, alert: models.Alert) -> list[models.Event]:
    """The specific events that caused this alert to fire, in chronological order."""
    if not alert.event_seqs:
        return []
    rows = session.scalars(
        select(models.Event)
        .where(models.Event.log_file_id == alert.log_file_id, models.Event.seq.in_(alert.event_seqs))
        .order_by(models.Event.timestamp, models.Event.seq)
    ).all()
    return list(rows)


def investigation_context(session: Session, alert: models.Alert, *, limit: int = 25) -> dict:
    """Bounded, explicitly related evidence for alert review; not a new detection verdict.

    Only match known source IP/account values. Never treat missing fields as a common
    indicator or pull unrelated events. This read-only helper does not alter evidence.
    """
    from sqlalchemy import or_

    limit = max(1, min(int(limit), 50))
    predicates = []
    if alert.source_ip:
        predicates.append(models.Event.source_ip == alert.source_ip)
    if alert.username:
        predicates.append(models.Event.username == alert.username)
    related = []
    if predicates:
        query = (select(models.Event)
                 .where(or_(*predicates), models.Event.log_file_id != alert.log_file_id)
                 .order_by(models.Event.timestamp.desc(), models.Event.id.desc())
                 .limit(limit))
        related = list(session.scalars(query))
    return {"related_events": related, "limit": limit}


def ioc_context_event(session: Session, ioc: models.IOC) -> models.Event | None:
    return session.get(models.Event, ioc.event_id)


# --------------------------------------------------------------------------- detections (rule-level)
def detection_rule_stats(session: Session, since_ts=None) -> list[dict]:
    """One row per rule that has fired at least once, with a total match count. Uses the Detection
    table (every rule firing, not just those that crossed the alert threshold) so a low-severity
    rule that fires constantly is still visible here, distinct from the Alerts triage queue."""
    query = select(models.Detection.rule_id, models.Detection.rule_name, models.Detection.category,
                   func.count().label("n"))
    if since_ts is not None:
        query = query.where(models.Detection.timestamp >= since_ts)
    query = query.group_by(models.Detection.rule_id, models.Detection.rule_name, models.Detection.category)
    rows = session.execute(query.order_by(func.count().desc())).all()
    # Current severity/response come from the live rule catalogue, not the stored row, so a
    # rule's documentation always reflects its current definition even for old detections.
    from regexsoc.rules import load_rules

    catalogue = {r.id: r for r in load_rules()}
    out = []
    for rule_id, rule_name, category, n in rows:
        rule = catalogue.get(rule_id)
        out.append({"rule_id": rule_id, "rule_name": rule_name, "category": category, "matches": n,
                   "severity": rule.severity if rule else "LOW", "enabled": rule.enabled if rule else True})
    return out


def alerts_for_rule(session: Session, rule_id: str, limit: int = 100) -> list[models.Alert]:
    return list(session.scalars(
        select(models.Alert).where(models.Alert.rule_id == rule_id)
        .order_by(models.Alert.timestamp.desc()).limit(limit)
    ))


# --------------------------------------------------------------------------- IOCs (aggregated by value)
def ioc_aggregate_list(session: Session, ioc_type: str | None = None, value_contains: str | None = None,
                       page: int = 1, page_size: int = 25) -> tuple[list[dict], int]:
    """One row per distinct (type, value) across the whole database, with first/last seen and a
    count — matching how an analyst actually thinks about an indicator, rather than one row per
    times it happened to be extracted."""
    base = select(models.IOC.ioc_type, models.IOC.value, func.count().label("n"),
                 func.min(models.IOC.timestamp).label("first_seen"),
                 func.max(models.IOC.timestamp).label("last_seen"))
    if ioc_type:
        base = base.where(models.IOC.ioc_type == ioc_type)
    if value_contains:
        base = base.where(models.IOC.value.contains(value_contains))
    base = base.group_by(models.IOC.ioc_type, models.IOC.value)
    total = session.scalar(select(func.count()).select_from(base.subquery())) or 0
    rows = session.execute(
        base.order_by(func.max(models.IOC.timestamp).desc()).offset((page - 1) * page_size).limit(page_size)
    ).all()
    out = [{"ioc_type": t, "value": v, "occurrences": n, "first_seen": first, "last_seen": last,
           "risk": _ioc_risk(session, t, v)} for t, v, n, first, last in rows]
    return out, total


def ioc_detail_aggregate(session: Session, ioc_type: str, value: str) -> dict | None:
    row = session.execute(
        select(func.count(), func.min(models.IOC.timestamp), func.max(models.IOC.timestamp))
        .where(models.IOC.ioc_type == ioc_type, models.IOC.value == value)
    ).one()
    count, first_seen, last_seen = row
    if count == 0:
        return None
    sample = session.scalar(
        select(models.IOC).where(models.IOC.ioc_type == ioc_type, models.IOC.value == value)
        .order_by(models.IOC.id.desc())
    )
    related = related_alerts_for_ioc(session, ioc_type, value)
    return {"ioc_type": ioc_type, "value": value, "occurrences": count, "first_seen": first_seen,
           "last_seen": last_seen, "context": sample.context if sample else "", "rule_id": sample.rule_id if sample else "",
           "risk": _ioc_risk(session, ioc_type, value), "related_alerts": related}


def related_alerts_for_ioc(session: Session, ioc_type: str, value: str, limit: int = 10) -> list[models.Alert]:
    """Alerts plausibly connected to this indicator. Only IP-type IOCs have a direct, reliable
    join (Alert.source_ip); other types have no such column on Alert, so we do not guess."""
    if ioc_type not in ("IPV4", "IPV6"):
        return []
    return list(session.scalars(
        select(models.Alert).where(models.Alert.source_ip == value)
        .order_by(models.Alert.risk_score.desc()).limit(limit)
    ))


def _ioc_risk(session: Session, ioc_type: str, value: str) -> str:
    """An IOC has no risk score of its own (extraction is not scored); its risk is derived from
    whether it is tied to any alert, and if so, the highest severity among those alerts."""
    alerts = related_alerts_for_ioc(session, ioc_type, value, limit=1000)
    if not alerts:
        return "UNKNOWN"
    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    return max(alerts, key=lambda a: order.get(a.severity, 0)).severity


def notification_count(session: Session) -> int:
    """New, high-priority alerts — drives the notification bell in the topbar on every page."""
    return session.scalar(
        select(func.count()).select_from(models.Alert)
        .where(models.Alert.status == "New", models.Alert.severity.in_(("CRITICAL", "HIGH")))
    ) or 0


class SearchResults:
    def __init__(self) -> None:
        self.alerts: list[models.Alert] = []
        self.events: list[models.Event] = []
        self.iocs: list[models.IOC] = []
        self.alert_total = self.event_total = self.ioc_total = 0

    @property
    def total(self) -> int:
        return self.alert_total + self.event_total + self.ioc_total


def search(session: Session, query: SearchQuery) -> SearchResults:
    """Dispatch a classified query to the right column(s) across alerts, events and IOCs."""
    results = SearchResults()
    limit = RESULTS_PER_SEARCH_SECTION

    if query.kind == "alert_id":
        alert = session.scalar(select(models.Alert).where(models.Alert.alert_id == query.value))
        results.alerts = [alert] if alert else []
        results.alert_total = len(results.alerts)
        return results

    if query.kind == "ip":
        a_q = select(models.Alert).where(models.Alert.source_ip == query.value)
        e_q = select(models.Event).where(
            (models.Event.source_ip == query.value) | (models.Event.destination_ip == query.value)
        )
        i_q = select(models.IOC).where(models.IOC.value == query.value)
    elif query.kind == "hash":
        i_q = select(models.IOC).where(models.IOC.value == query.value)
        a_q = e_q = None
    elif query.kind in ("cve", "domain_or_url"):
        i_q = select(models.IOC).where(models.IOC.value.contains(query.value))
        a_q = e_q = None
    else:  # free text: username, rule name, or a request path fragment
        like = f"%{query.value}%"
        a_q = select(models.Alert).where(
            models.Alert.username.contains(query.value) | models.Alert.rule_name.ilike(like)
            | models.Alert.source_ip.contains(query.value)
        )
        e_q = select(models.Event).where(
            models.Event.username.contains(query.value) | models.Event.http_path.ilike(like)
            | models.Event.host.contains(query.value)
        )
        i_q = select(models.IOC).where(models.IOC.value.contains(query.value))

    if a_q is not None:
        results.alert_total = session.scalar(select(func.count()).select_from(a_q.subquery())) or 0
        results.alerts = list(session.scalars(a_q.order_by(models.Alert.id.desc()).limit(limit)))
    if e_q is not None:
        results.event_total = session.scalar(select(func.count()).select_from(e_q.subquery())) or 0
        results.events = list(session.scalars(e_q.order_by(models.Event.id.desc()).limit(limit)))
    results.ioc_total = session.scalar(select(func.count()).select_from(i_q.subquery())) or 0
    results.iocs = list(session.scalars(i_q.order_by(models.IOC.id.desc()).limit(limit)))
    return results


def acknowledgement_metrics(session: Session) -> dict:
    """Metrics over rows with both original alert timestamp and first acknowledgement.

    Exclude missing or reversed timestamps; never substitute updated_at or ingestion time.
    Durations are seconds and represent first acknowledgement, not resolution.
    """
    rows = session.execute(select(models.Alert.timestamp, models.Alert.acknowledged_at).where(
        models.Alert.timestamp.is_not(None), models.Alert.acknowledged_at.is_not(None)
    )).all()
    durations = [(ack - created).total_seconds() for created, ack in rows if ack >= created]
    return {
        "acknowledged": session.scalar(select(func.count()).select_from(models.Alert).where(
            models.Alert.acknowledged_at.is_not(None))) or 0,
        "pending": session.scalar(select(func.count()).select_from(models.Alert).where(
            models.Alert.acknowledged_at.is_(None),
            models.Alert.status.in_(("New", "Investigating")))) or 0,
        "mean_time_to_ack_seconds": round(sum(durations) / len(durations), 1) if durations else None,
        "sample_size": len(durations),
    }
