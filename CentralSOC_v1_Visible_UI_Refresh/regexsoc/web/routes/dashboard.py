"""The SOC console: overview, alerts, events, IOCs, detections, rules, log analysis, reports,
settings, and global search.

Server-rendered (Jinja2) pages backed by the same services used by the CLI and REST API — nothing
here is a separate code path, so behavior stays consistent across all three interfaces.
"""

from __future__ import annotations
from regexsoc.security.rbac import ASSIGNABLE_ROLES, ROLE_LABELS

from flask import (
    Blueprint, Response, current_app, flash, g, redirect, render_template, request, session, url_for,
)
from sqlalchemy import case, func, select

from regexsoc.db import dashboard_queries as q
from regexsoc.db import models
from regexsoc.db.alert_queue import build_alert_queue, normalize_alert_filters
from regexsoc.db.auth_service import InvalidCredentials, change_password, disable_mfa
from regexsoc.db.service import add_alert_note, alert_activity, update_alert_status, assign_alert, acknowledge_alert, set_alert_verdict, record_audit
from regexsoc.security.audit import AuditAction
from regexsoc.rules import UnknownRuleError, load_rules, set_enabled
from regexsoc.security.rbac import has_permission
from regexsoc.services.export import to_csv, to_json
from regexsoc.web.csrf_middleware import current_token
from regexsoc.web.decorators import login_required, permission_required
from regexsoc.web.search import classify
from regexsoc.web.timerange import DEFAULT_RANGE, LABELS as TIME_RANGE_LABELS, is_valid as is_valid_range, since
from regexsoc.web.upload import UploadRejected, handle_upload

bp = Blueprint("dashboard", __name__, url_prefix="")

PAGE_SIZE = 25
MAX_LOG_FILES_PER_BATCH = 8


def _ctx(active: str, **extra) -> dict:
    """Context shared by every dashboard page: nav state, RBAC flags, CSRF token, notification count."""
    role = g.current_user.role
    return {
        "active": active,
        "can_view_rules": has_permission(role, "view_rules"),
        "can_view_incidents": has_permission(role, "view_incidents"),
        "can_manage_rules": has_permission(role, "manage_rules"),
        "can_update_alert_status": has_permission(role, "update_alert_status"),
        "can_assign_alerts": has_permission(role, "assign_alerts"),
        "can_upload_logs": has_permission(role, "upload_logs"),
        "csrf_token": current_token(session, current_app.config["SECRET_KEY"]),
        "time_range_labels": TIME_RANGE_LABELS,
        "new_alert_count": q.notification_count(g.db),
        **extra,
    }


def _page() -> int:
    try:
        return max(1, int(request.args.get("page", 1)))
    except ValueError:
        return 1


def _query_args(exclude=("page",)) -> dict:
    return {k: v for k, v in request.args.items() if k not in exclude and v}


def _time_range() -> str:
    value = request.args.get("time_range", DEFAULT_RANGE)
    return value if is_valid_range(value) else DEFAULT_RANGE


# --------------------------------------------------------------------------- overview
@bp.get("/")
@permission_required("view_statistics")
def overview():
    stats = q.overview_stats(g.db)
    window = request.args.get("days", "7")
    days = None if window == "all" else (int(window) if window in ("7", "30") else 7)
    max_ip = max((n for _, n in stats["top_source_ips"]), default=0)
    max_cat = max((n for _, n in stats["detection_categories"]), default=0)
    can_view_incidents = has_permission(g.current_user.role, "view_incidents")
    return render_template("dashboard/overview.html", **_ctx("overview", stats=stats,
                           incident_stats=q.incident_overview(g.db) if can_view_incidents else None,
                           analytics=q.analytics_overview(g.db, days=days),
                           workload=q.analyst_workload(g.db) if has_permission(g.current_user.role, "view_alerts") else None,
                           acknowledgement=q.acknowledgement_metrics(g.db) if has_permission(g.current_user.role, "view_alerts") else None,
                           detection_stats=q.detection_overview(g.db),
                           recent=q.recent_alerts(g.db, 10), max_ip=max_ip, max_cat=max_cat))


# --------------------------------------------------------------------------- alerts
@bp.get("/alerts")
@permission_required("view_alerts")
def alerts_list():
    filters = normalize_alert_filters(request.args)
    query = build_alert_queue(filters, since(filters["time_range"]), g.current_user.username)
    page = min(_page(), 100000)  # cap untrusted pagination arithmetic
    total = g.db.scalar(select(func.count()).select_from(query.subquery())) or 0
    ordering = {
        "risk": (models.Alert.risk_score.desc(), models.Alert.id.desc()),
        "newest": (models.Alert.timestamp.desc(), models.Alert.id.desc()),
        "oldest": (models.Alert.timestamp.asc(), models.Alert.id.asc()),
    }
    rows = g.db.scalars(query.order_by(*ordering[filters["sort"]])
                        .offset((page - 1) * PAGE_SIZE).limit(PAGE_SIZE)).all()
    detections = sorted({(r[0], r[1]) for r in g.db.execute(select(models.Alert.rule_id, models.Alert.rule_name).distinct())})
    scoped = query.order_by(None).subquery()
    summary = g.db.execute(select(
        func.coalesce(func.sum(case((scoped.c.status == "New", 1), else_=0)), 0),
        func.coalesce(func.sum(case((scoped.c.assigned_to == g.current_user.username, 1), else_=0)), 0),
        func.coalesce(func.sum(case((scoped.c.risk_score >= 80, 1), else_=0)), 0),
        func.coalesce(func.sum(case((scoped.c.analyst_verdict.is_(None), 1), else_=0)), 0),
    )).one()
    return render_template("dashboard/alerts.html", **_ctx("alerts", alerts=rows, page=page,
                           page_size=PAGE_SIZE, total=total, filters=filters, qargs=_query_args(), summary=summary,
                           statuses=models.ALERT_STATUSES, detections=detections))


@bp.get("/alerts/<int:alert_pk>")
@permission_required("view_alerts")
def alert_detail(alert_pk: int):
    alert = g.db.get(models.Alert, alert_pk)
    if alert is None:
        return render_template("dashboard/not_found.html", **_ctx("alerts", kind="alert")), 404
    timeline = q.alert_timeline(g.db, alert)
    stamps = [e.timestamp for e in timeline if e.timestamp]
    span = {"occurrences": len(timeline), "first_seen": min(stamps) if stamps else alert.timestamp,
           "last_seen": max(stamps) if stamps else alert.timestamp,
           "target": next((e.host or e.destination_ip for e in timeline if e.host or e.destination_ip), None)}
    can_view_events = has_permission(g.current_user.role, "view_events")
    can_view_incidents = has_permission(g.current_user.role, "view_incidents")
    context = q.investigation_context(g.db, alert) if can_view_events else {"related_events": [], "limit": 25}
    linked_incidents = (list(g.db.scalars(select(models.Incident).join(
        models.IncidentAlert, models.IncidentAlert.incident_id == models.Incident.id).where(
        models.IncidentAlert.alert_id == alert.id).order_by(models.Incident.id.desc()).limit(20)))
        if can_view_incidents else [])
    return render_template("dashboard/alert_detail.html", **_ctx("alerts", alert=alert, timeline=timeline,
                           span=span, statuses=models.ALERT_STATUSES, activity=alert_activity(g.db, alert.alert_id),
                           can_view_events=can_view_events, linked_incidents=linked_incidents,
                           eligible_analysts=(g.db.scalars(select(models.User).where(
                               models.User.is_active.is_(True), models.User.role.in_(tuple(ASSIGNABLE_ROLES)))
                               .order_by(models.User.username)).all() if has_permission(g.current_user.role, "assign_alerts") else []),
                           **context))


@bp.post("/alerts/<int:alert_pk>/status")
@permission_required("update_alert_status")
def alert_update_status(alert_pk: int):
    alert = g.db.get(models.Alert, alert_pk)
    if alert is None:
        return render_template("dashboard/not_found.html", **_ctx("alerts", kind="alert")), 404
    try:
        update_alert_status(g.db, alert.alert_id, request.form.get("status", ""), g.current_user.username,
                            ip_address=request.remote_addr, note=request.form.get("note") or None)
        flash(f"{alert.alert_id} is now {alert.status}.")
    except ValueError as exc:
        flash(str(exc))
    return redirect(url_for("dashboard.alert_detail", alert_pk=alert_pk))


@bp.post("/alerts/<int:alert_pk>/notes")
@permission_required("update_alert_status")
def alert_add_note(alert_pk: int):
    alert = g.db.get(models.Alert, alert_pk)
    if alert is None:
        return render_template("dashboard/not_found.html", **_ctx("alerts", kind="alert")), 404
    try:
        add_alert_note(g.db, alert.alert_id, request.form.get("note", ""), g.current_user.username,
                       ip_address=request.remote_addr)
        flash("Analyst note saved.")
    except ValueError as exc:
        flash(str(exc))
    return redirect(url_for("dashboard.alert_detail", alert_pk=alert_pk))


@bp.post("/alerts/<int:alert_pk>/acknowledge")
@permission_required("update_alert_status")
def alert_acknowledge(alert_pk: int):
    alert = g.db.get(models.Alert, alert_pk)
    if alert is None:
        return render_template("dashboard/not_found.html", **_ctx("alerts", kind="alert")), 404
    acknowledge_alert(g.db, alert.alert_id, g.current_user.username, ip_address=request.remote_addr)
    flash("Alert acknowledged." if alert.acknowledged_by == g.current_user.username else "Already acknowledged.")
    return redirect(url_for("dashboard.alert_detail", alert_pk=alert_pk))


@bp.post("/alerts/<int:alert_pk>/assign")
@permission_required("assign_alerts")
def alert_assign(alert_pk: int):
    alert = g.db.get(models.Alert, alert_pk)
    if alert is None:
        return render_template("dashboard/not_found.html", **_ctx("alerts", kind="alert")), 404
    try:
        assign_alert(g.db, alert.alert_id, request.form.get("assigned_to", ""),
                     g.current_user.username, ip_address=request.remote_addr)
        flash("Alert assignment updated.")
    except ValueError as exc:
        flash(str(exc))
    return redirect(url_for("dashboard.alert_detail", alert_pk=alert_pk))


@bp.post("/alerts/<int:alert_pk>/verdict")
@permission_required("update_alert_status")
def alert_set_verdict(alert_pk: int):
    alert = g.db.get(models.Alert, alert_pk)
    if alert is None:
        return render_template("dashboard/not_found.html", **_ctx("alerts", kind="alert")), 404
    try:
        set_alert_verdict(g.db, alert.alert_id, request.form.get("verdict", ""),
                          request.form.get("reason", ""), g.current_user.username,
                          ip_address=request.remote_addr)
        flash("Analyst verdict recorded.")
    except ValueError as exc:
        flash(str(exc))
    return redirect(url_for("dashboard.alert_detail", alert_pk=alert_pk))


@bp.get("/alerts/export.csv")
@permission_required("view_alerts")
def alerts_queue_export():
    """Export up to 1,000 alerts matching the current, validated queue filters."""
    filters = normalize_alert_filters(request.args)
    query = build_alert_queue(filters, since(filters["time_range"]), g.current_user.username)
    ordering = {
        "risk": (models.Alert.risk_score.desc(), models.Alert.id.desc()),
        "newest": (models.Alert.timestamp.desc(), models.Alert.id.desc()),
        "oldest": (models.Alert.timestamp.asc(), models.Alert.id.asc()),
    }
    rows = g.db.scalars(query.order_by(*ordering[filters["sort"]]).limit(1000)).all()
    fields = ["alert_id", "timestamp_utc", "severity", "risk_score", "rule_id", "rule_name",
              "source_ip", "username", "status", "assigned_to", "analyst_verdict", "verdict_reason"]
    data = [{"alert_id": a.alert_id, "timestamp_utc": a.timestamp.isoformat() if a.timestamp else "",
             "severity": a.severity, "risk_score": a.risk_score, "rule_id": a.rule_id,
             "rule_name": a.rule_name, "source_ip": a.source_ip, "username": a.username,
             "status": a.status, "assigned_to": a.assigned_to,
             "analyst_verdict": a.analyst_verdict, "verdict_reason": a.verdict_reason}
            for a in rows]
    record_audit(g.db, AuditAction.ALERT_QUEUE_EXPORTED, g.current_user.username, "SUCCESS",
                 ip_address=request.remote_addr, detail={"rows": len(rows), "limit": 1000})
    return Response(to_csv(data, fields), mimetype="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="centralsoc-alert-handoff.csv"',
                             "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


# --------------------------------------------------------------------------- events
@bp.get("/events")
@permission_required("view_events")
def events_list():
    query = select(models.Event)
    time_range = _time_range()
    filters = {"severity": request.args.get("severity", "").upper(), "event_type": request.args.get("event_type", ""),
              "source_ip": request.args.get("source_ip", "").strip(), "destination_ip": request.args.get("destination_ip", "").strip(),
              "username": request.args.get("username", "").strip(), "time_range": time_range}
    if filters["severity"]:
        query = query.where(models.Event.severity == filters["severity"])
    if filters["event_type"]:
        query = query.where(models.Event.event_type == filters["event_type"])
    if filters["source_ip"]:
        query = query.where(models.Event.source_ip == filters["source_ip"])
    if filters["destination_ip"]:
        query = query.where(models.Event.destination_ip == filters["destination_ip"])
    if filters["username"]:
        query = query.where(models.Event.username == filters["username"])
    cutoff = since(time_range)
    if cutoff is not None:
        query = query.where(models.Event.timestamp >= cutoff)
    page = _page()
    total = g.db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = g.db.scalars(query.order_by(models.Event.id.desc()).offset((page - 1) * PAGE_SIZE).limit(PAGE_SIZE)).all()
    event_types = sorted({r[0] for r in g.db.execute(select(models.Event.event_type).distinct())})
    return render_template("dashboard/events.html", **_ctx("events", events=rows, page=page, page_size=PAGE_SIZE,
                           total=total, filters=filters, qargs=_query_args(), event_types=event_types))


@bp.get("/events/<int:event_id>")
@permission_required("view_events")
def event_detail(event_id: int):
    event = g.db.get(models.Event, event_id)
    if event is None:
        return render_template("dashboard/not_found.html", **_ctx("events", kind="event")), 404
    iocs = g.db.scalars(select(models.IOC).where(models.IOC.event_id == event_id)).all()
    return render_template("dashboard/event_detail.html", **_ctx("events", event=event, iocs=iocs))


# --------------------------------------------------------------------------- IOCs (aggregated by value)
@bp.get("/iocs")
@permission_required("view_iocs")
def iocs_list():
    filters = {"type": request.args.get("type", "").upper(), "value": request.args.get("value", "").strip(),
              "risk": request.args.get("risk", "").upper()}
    page = _page()
    rows, total_unfiltered = q.ioc_aggregate_list(g.db, filters["type"] or None, filters["value"] or None,
                                                  page=page, page_size=PAGE_SIZE * 4)  # over-fetch to allow risk filtering below
    if filters["risk"]:
        rows = [r for r in rows if r["risk"] == filters["risk"]]
    total = len(rows) if filters["risk"] else total_unfiltered
    rows = rows[:PAGE_SIZE]
    ioc_types = sorted({r[0] for r in g.db.execute(select(models.IOC.ioc_type).distinct())})
    return render_template("dashboard/iocs.html", **_ctx("iocs", iocs=rows, page=page, page_size=PAGE_SIZE,
                           total=total, filters=filters, qargs=_query_args(), ioc_types=ioc_types))


@bp.get("/iocs/<ioc_type>/<path:value>")
@permission_required("view_iocs")
def ioc_detail(ioc_type: str, value: str):
    detail = q.ioc_detail_aggregate(g.db, ioc_type.upper(), value)
    if detail is None:
        return render_template("dashboard/not_found.html", **_ctx("iocs", kind="IOC")), 404
    return render_template("dashboard/ioc_detail.html", **_ctx("iocs", ioc=detail))


# --------------------------------------------------------------------------- detections (rule-level)
@bp.get("/detections")
@permission_required("view_alerts")
def detections_list():
    time_range = _time_range()
    rows = q.detection_rule_stats(g.db, since(time_range))
    return render_template("dashboard/detections.html", **_ctx("detections", detections=rows,
                           filters={"time_range": time_range}))


@bp.get("/detections/<rule_id>")
@permission_required("view_alerts")
def detection_detail(rule_id: str):
    rule = next((r for r in load_rules() if r.id == rule_id.upper()), None)
    if rule is None:
        return render_template("dashboard/not_found.html", **_ctx("detections", kind="detection")), 404
    alerts = q.alerts_for_rule(g.db, rule.id)
    return render_template("dashboard/detection_detail.html", **_ctx("detections", rule=rule, alerts=alerts))


# --------------------------------------------------------------------------- rules
@bp.get("/rules")
@permission_required("view_rules")
def rules_list():
    rules = load_rules()
    category = request.args.get("category", "")
    search_term = request.args.get("q", "").strip().lower()
    if category:
        rules = [r for r in rules if r.category == category]
    if search_term:
        rules = [r for r in rules if search_term in r.name.lower() or search_term in r.id.lower()]
    categories = sorted({r.category for r in load_rules()})
    return render_template("dashboard/rules.html", **_ctx("rules", rules=rules, categories=categories,
                           selected_category=category, search_term=request.args.get("q", "")))


@bp.post("/rules/<rule_id>/toggle")
@permission_required("manage_rules")
def rule_toggle(rule_id: str):
    try:
        rule = set_enabled(rule_id, request.form.get("enabled") == "1")
        flash(f"{rule.id} is now {'enabled' if rule.enabled else 'disabled'}.")
    except UnknownRuleError:
        flash(f"Unknown rule {rule_id}.")
    return redirect(url_for("dashboard.rules_list"))


# --------------------------------------------------------------------------- log analysis
@bp.get("/log-analysis")
@permission_required("upload_logs")
def log_analysis_form():
    return render_template("dashboard/log_analysis.html", **_ctx("log_analysis"))


@bp.post("/log-analysis")
@permission_required("upload_logs")
def log_analysis_submit():
    # getlist() also handles the historical single-file field name, so existing clients work.
    files = request.files.getlist("file")
    if not files or any(not item.filename for item in files):
        flash("Select one or more log files before uploading.")
        return redirect(url_for("dashboard.log_analysis_form"))
    if len(files) > MAX_LOG_FILES_PER_BATCH:
        flash(f"A batch can contain at most {MAX_LOG_FILES_PER_BATCH} files.")
        return redirect(url_for("dashboard.log_analysis_form"))

    results = []
    for item in files:
        # A malformed file should not prevent analysts from seeing the result of good files.
        # The SAVEPOINT also rolls back any database writes associated with a rejected file.
        try:
            with g.db.begin_nested():
                result = handle_upload(g.db, item, uploaded_by=g.current_user.username,
                                       ip_address=request.remote_addr)
            results.append({"name": item.filename, "ok": True, "duplicate": result.duplicate,
                            "log_file_id": result.log_file.id, "events": result.events,
                            "alerts": result.alerts})
        except UploadRejected as exc:
            results.append({"name": item.filename, "ok": False, "error": str(exc)})

    if len(files) == 1:
        result = results[0]
        if not result["ok"]:
            flash(result["error"])
            return redirect(url_for("dashboard.log_analysis_form"))
        if result["duplicate"]:
            flash("This file has already been analyzed (identical content); showing the existing result.")
        return redirect(url_for("dashboard.log_analysis_result", log_file_id=result["log_file_id"]))

    return render_template("dashboard/log_analysis_batch.html", **_ctx("log_analysis", results=results,
                           success_count=sum(r["ok"] for r in results),
                           failure_count=sum(not r["ok"] for r in results)))


@bp.get("/log-analysis/<int:log_file_id>")
@permission_required("view_events")
def log_analysis_result(log_file_id: int):
    log_file = g.db.get(models.LogFile, log_file_id)
    if log_file is None:
        return render_template("dashboard/not_found.html", **_ctx("log_analysis", kind="log file")), 404
    summary = q.log_file_summary(g.db, log_file_id)
    page = _page()
    events, total = q.log_file_events(g.db, log_file_id, page=page, page_size=PAGE_SIZE)
    return render_template("dashboard/log_analysis_result.html", **_ctx("log_analysis", log_file=log_file,
                           summary=summary, events=events, page=page, page_size=PAGE_SIZE, total=total,
                           qargs=_query_args() | {"log_file_id": log_file_id}))


# --------------------------------------------------------------------------- reports
DATASETS = {
    "alerts": ("view_alerts", models.Alert, ["alert_id", "rule_id", "rule_name", "severity", "risk_score",
              "source_ip", "username", "status", "timestamp"]),
    "events": ("view_events", models.Event, ["id", "event_type", "severity", "source_ip", "destination_ip",
              "username", "http_path", "http_status", "timestamp"]),
    "iocs": ("view_iocs", models.IOC, ["ioc_type", "value", "rule_id", "timestamp"]),
}


@bp.get("/reports")
@login_required
def reports_page():
    available = [name for name, (perm, *_) in DATASETS.items() if has_permission(g.current_user.role, perm)]
    return render_template("dashboard/reports.html", **_ctx("reports", datasets=available))


@bp.get("/reports/export/<dataset>.<fmt>")
@login_required
def reports_export(dataset: str, fmt: str):
    if dataset not in DATASETS or fmt not in ("csv", "json"):
        return render_template("dashboard/not_found.html", **_ctx("reports", kind="report")), 404
    permission, model, fields = DATASETS[dataset]
    if not has_permission(g.current_user.role, permission):
        return render_template("dashboard/not_found.html", **_ctx("reports", kind="report")), 403
    rows = g.db.scalars(select(model).order_by(model.id.desc()).limit(5000)).all()
    dicts = [{f: getattr(r, f) for f in fields} for r in rows]
    body = to_csv(dicts, fields) if fmt == "csv" else to_json(dicts)
    mimetype = "text/csv" if fmt == "csv" else "application/json"
    record_audit(g.db, AuditAction.REPORT_EXPORTED, g.current_user.username, "SUCCESS",
                 ip_address=request.remote_addr,
                 detail={"dataset": dataset, "format": fmt, "rows": len(rows), "limit": 5000})
    return Response(body, mimetype=mimetype,
                    headers={"Content-Disposition": f'attachment; filename="{dataset}.{fmt}"',
                             "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


# --------------------------------------------------------------------------- settings
@bp.get("/settings")
@login_required
def settings_page():
    from regexsoc import config

    return render_template("dashboard/settings.html", **_ctx("settings",
                           session_minutes=config.session_lifetime_minutes()))


@bp.post("/settings/password")
@login_required
def settings_change_password():
    if g.current_user.username.casefold() == "demo_viewer":
        return "Security settings are locked for this demo account.", 403

    try:
        change_password(
            g.db,
            g.current_user.id,
            request.form.get("current_password", ""),
            request.form.get("new_password", ""),
            ip_address=request.remote_addr,
        )
        flash("Password changed.")
    except InvalidCredentials:
        flash("Current password is incorrect.")
    except ValueError as exc:
        flash(str(exc))
    return redirect(url_for("dashboard.settings_page"))


@bp.post("/settings/mfa/disable")
@login_required
def settings_disable_mfa():
    if g.current_user.username.casefold() == "demo_viewer":
        return "Security settings are locked for this demo account.", 403

    disable_mfa(
        g.db,
        g.current_user.id,
        disabled_by=g.current_user.username,
        ip_address=request.remote_addr,
    )
    flash("Two-factor authentication disabled.")
    return redirect(url_for("dashboard.settings_page"))


# --------------------------------------------------------------------------- search
@bp.get("/search")
@login_required
def search_results():
    raw = request.args.get("q", "").strip()
    if not raw:
        return render_template("dashboard/search.html", **_ctx("overview", query=None, results=None))
    parsed = classify(raw)
    results = q.search(g.db, parsed)
    return render_template("dashboard/search.html", **_ctx("overview", query=raw, kind=parsed.kind, results=results))


@bp.get("/security-memory")
@permission_required("view_alerts")
def security_memory():
    """Entity history includes unreviewed alerts; decisions remain explicitly identified."""
    from ipaddress import ip_address
    term = request.args.get("q", "").strip()[:255]
    reviewed = request.args.get("reviewed") == "1"
    try:
        ip = str(ip_address(term))
    except ValueError:
        ip = None
    query = select(models.Alert)
    if term:
        if ip:
            query = query.where(models.Alert.source_ip.in_({term, ip}))
        else:
            query = query.where(models.Alert.rule_name.contains(term, autoescape=True)
                                | models.Alert.source_ip.contains(term, autoescape=True)
                                | models.Alert.username.contains(term, autoescape=True)
                                | models.Alert.alert_id.contains(term, autoescape=True))
    if reviewed:
        query = query.where(models.Alert.analyst_verdict.is_not(None))
    total = g.db.scalar(select(func.count()).select_from(query.subquery())) or 0
    decisions = g.db.scalar(select(func.count()).select_from(
        query.where(models.Alert.analyst_verdict.is_not(None)).subquery())) or 0
    page = min(_page(), 100000)
    memories = g.db.scalars(query.order_by(models.Alert.timestamp.desc(), models.Alert.id.desc())
                            .offset((page - 1) * PAGE_SIZE).limit(PAGE_SIZE)).all()
    events, indicators, event_total, ioc_total = [], [], 0, 0
    if ip and has_permission(g.current_user.role, "view_events"):
        event_query = select(models.Event).where(models.Event.source_ip.in_({term, ip})
                                                | models.Event.destination_ip.in_({term, ip}))
        event_total = g.db.scalar(select(func.count()).select_from(event_query.subquery())) or 0
        events = g.db.scalars(event_query.order_by(models.Event.timestamp.desc(), models.Event.id.desc()).limit(25)).all()
    if ip and has_permission(g.current_user.role, "view_iocs"):
        ioc_query = select(models.IOC).where(models.IOC.value.in_({term, ip}))
        ioc_total = g.db.scalar(select(func.count()).select_from(ioc_query.subquery())) or 0
        indicators = g.db.scalars(ioc_query.order_by(models.IOC.id.desc()).limit(25)).all()
    return render_template("dashboard/security_memory.html", **_ctx("memory", memories=memories,
                           term=term, total=total, decisions=decisions, reviewed=reviewed, ip=ip,
                           events=events, indicators=indicators, event_total=event_total, ioc_total=ioc_total,
                           page=page, page_size=PAGE_SIZE, qargs={"q": term, "reviewed": "1" if reviewed else ""}))
