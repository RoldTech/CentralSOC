"""REST API.

Deviations from the original spec, documented here and in docs/api.md:
- POST /api/rules: rules are a fixed, code-defined catalogue (see regexsoc/rules/definitions.py), not
  user-created, so this returns 501 Not Implemented with an explanatory message rather than silently
  accepting a rule it would not use.
- PATCH /api/rules/<id> toggles enabled/disabled (the only mutable property of a rule today).
- GET /api/whoami is an addition (not in the original spec): returns the caller's own identity and
  permissions, useful for a future frontend to render role-appropriate UI.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from flask import Blueprint, current_app, g, jsonify, request, session
from sqlalchemy import select

from regexsoc import config
from regexsoc.db import models
from regexsoc.db.service import update_alert_status
from regexsoc.rules import UnknownRuleError, load_rules, set_enabled
from regexsoc.security.rbac import permissions_for
from regexsoc.services.export import to_csv, to_json
from regexsoc.web.csrf_middleware import current_token
from regexsoc.web.decorators import login_required, permission_required
from regexsoc.web.upload import UploadRejected, handle_upload

bp = Blueprint("api", __name__, url_prefix="/api")

DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE = 50, 500


@bp.get("/csrf-token")
def csrf_token_route():
    """A CSRF token for the current session, for JS-driven forms and API clients (a plain <form> page
    embeds its own token instead; see templates/auth/*.html). Available pre-login too, since the
    double-submit token is bound to the session, not to a user."""
    return jsonify(csrf_token=current_token(session, current_app.config["SECRET_KEY"]))


def _paginate():
    try:
        page = max(1, int(request.args.get("page", 1)))
        page_size = min(MAX_PAGE_SIZE, max(1, int(request.args.get("page_size", DEFAULT_PAGE_SIZE))))
    except ValueError:
        page, page_size = 1, DEFAULT_PAGE_SIZE
    return page, page_size


@bp.get("/whoami")
@login_required
def whoami():
    user = g.current_user
    return jsonify(username=user.username, role=user.role, mfa_enabled=user.mfa_enabled,
                   permissions=sorted(permissions_for(user.role)))


# --------------------------------------------------------------------------- events
@bp.get("/events")
@permission_required("view_events")
def list_events():
    query = select(models.Event)
    if source_ip := request.args.get("source_ip"):
        query = query.where(models.Event.source_ip == source_ip)
    if username := request.args.get("username"):
        query = query.where(models.Event.username == username)
    if event_type := request.args.get("event_type"):
        query = query.where(models.Event.event_type == event_type.upper())
    if severity := request.args.get("severity"):
        query = query.where(models.Event.severity == severity.upper())
    page, page_size = _paginate()
    rows = g.db.scalars(query.order_by(models.Event.id.desc()).offset((page - 1) * page_size).limit(page_size)).all()
    return jsonify(page=page, page_size=page_size, events=[_event_dict(r) for r in rows])


@bp.get("/events/<int:event_id>")
@permission_required("view_events")
def get_event(event_id: int):
    row = g.db.get(models.Event, event_id)
    if row is None:
        return jsonify(error="event not found"), 404
    return jsonify(_event_dict(row))


def _event_dict(e: models.Event) -> dict:
    return {"id": e.id, "log_file_id": e.log_file_id, "seq": e.seq,
           "timestamp": e.timestamp.isoformat() if e.timestamp else None, "source_ip": e.source_ip,
           "destination_ip": e.destination_ip, "source_port": e.source_port,
           "destination_port": e.destination_port, "protocol": e.protocol, "username": e.username,
           "auth_status": e.auth_status, "http_method": e.http_method, "http_path": e.http_path,
           "http_status": e.http_status, "event_type": e.event_type, "severity": e.severity,
           "source_format": e.source_format, "raw_log": e.raw_log}


# --------------------------------------------------------------------------- alerts
@bp.get("/alerts")
@permission_required("view_alerts")
def list_alerts_route():
    query = select(models.Alert)
    if status := request.args.get("status"):
        query = query.where(models.Alert.status == status)
    if severity := request.args.get("severity"):
        query = query.where(models.Alert.severity == severity.upper())
    if source_ip := request.args.get("source_ip"):
        query = query.where(models.Alert.source_ip == source_ip)
    page, page_size = _paginate()
    rows = g.db.scalars(
        query.order_by(models.Alert.risk_score.desc()).offset((page - 1) * page_size).limit(page_size)
    ).all()
    return jsonify(page=page, page_size=page_size, alerts=[_alert_dict(a) for a in rows])


@bp.get("/alerts/<int:alert_pk>")
@permission_required("view_alerts")
def get_alert(alert_pk: int):
    row = g.db.get(models.Alert, alert_pk)
    if row is None:
        return jsonify(error="alert not found"), 404
    return jsonify(_alert_dict(row))


@bp.patch("/alerts/<int:alert_pk>")
@permission_required("update_alert_status")
def patch_alert(alert_pk: int):
    row = g.db.get(models.Alert, alert_pk)
    if row is None:
        return jsonify(error="alert not found"), 404
    body = request.get_json(silent=True) or {}
    new_status = body.get("status")
    if not new_status:
        return jsonify(error="'status' is required"), 400
    try:
        updated = update_alert_status(g.db, row.alert_id, new_status, g.current_user.username,
                                      ip_address=request.remote_addr, note=body.get("note"))
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    return jsonify(_alert_dict(updated))


def _alert_dict(a: models.Alert) -> dict:
    return {"id": a.id, "alert_id": a.alert_id, "log_file_id": a.log_file_id,
           "timestamp": a.timestamp.isoformat() if a.timestamp else None, "rule_id": a.rule_id,
           "rule_name": a.rule_name, "source_ip": a.source_ip, "username": a.username,
           "severity": a.severity, "risk_score": a.risk_score, "reason": a.reason, "status": a.status,
           "recommended_response": a.recommended_response, "updated_by": a.updated_by,
           "updated_at": a.updated_at.isoformat() if a.updated_at else None, "note": a.note}


# --------------------------------------------------------------------------- IOCs
@bp.get("/iocs")
@permission_required("view_iocs")
def list_iocs():
    query = select(models.IOC)
    if ioc_type := request.args.get("type"):
        query = query.where(models.IOC.ioc_type == ioc_type.upper())
    if value := request.args.get("value"):
        query = query.where(models.IOC.value == value)
    page, page_size = _paginate()
    rows = g.db.scalars(query.order_by(models.IOC.id.desc()).offset((page - 1) * page_size).limit(page_size)).all()
    return jsonify(page=page, page_size=page_size, iocs=[
        {"id": i.id, "ioc_type": i.ioc_type, "value": i.value, "event_id": i.event_id,
         "timestamp": i.timestamp.isoformat() if i.timestamp else None, "context": i.context,
         "rule_id": i.rule_id} for i in rows
    ])


# --------------------------------------------------------------------------- statistics
@bp.get("/statistics")
@permission_required("view_statistics")
def statistics():
    from sqlalchemy import func

    counts = dict(g.db.execute(select(models.Alert.severity, func.count()).group_by(models.Alert.severity)).all())
    return jsonify(
        total_events=g.db.scalar(select(func.count()).select_from(models.Event)) or 0,
        total_alerts=g.db.scalar(select(func.count()).select_from(models.Alert)) or 0,
        total_iocs=g.db.scalar(select(func.count()).select_from(models.IOC)) or 0,
        total_log_files=g.db.scalar(select(func.count()).select_from(models.LogFile)) or 0,
        alerts_by_severity={s: counts.get(s, 0) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
    )


# --------------------------------------------------------------------------- rules
@bp.get("/rules")
@permission_required("view_rules")
def list_rules_route():
    return jsonify(rules=[r.to_dict() for r in load_rules()])


@bp.post("/rules")
@permission_required("manage_rules")
def create_rule_route():
    return jsonify(error="custom rule creation is not supported; rules are defined in code "
                        "(regexsoc/rules/definitions.py). Use PATCH /api/rules/<id> to toggle one."), 501


@bp.patch("/rules/<rule_id>")
@permission_required("manage_rules")
def patch_rule(rule_id: str):
    body = request.get_json(silent=True) or {}
    if "enabled" not in body:
        return jsonify(error="'enabled' (boolean) is required"), 400
    try:
        rule = set_enabled(rule_id, bool(body["enabled"]))
    except UnknownRuleError:
        return jsonify(error=f"unknown rule {rule_id}"), 404
    return jsonify(rule.to_dict())


# --------------------------------------------------------------------------- upload
@bp.post("/logs/upload")
@permission_required("upload_logs")
def upload_log():
    if "file" not in request.files:
        return jsonify(error="multipart field 'file' is required"), 400
    try:
        result = handle_upload(g.db, request.files["file"], uploaded_by=g.current_user.username,
                               ip_address=request.remote_addr)
    except UploadRejected as exc:
        return jsonify(error=str(exc)), 400
    status = 200 if result.duplicate else 201
    return jsonify(log_file_id=result.log_file.id, duplicate=result.duplicate, events=result.events,
                  detections=result.detections, alerts=result.alerts, iocs=result.iocs), status
