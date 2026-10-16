"""Server-rendered incident management. All writes use request transaction and CSRF middleware."""
from flask import Blueprint, Response, current_app, flash, g, redirect, render_template, request, session, url_for
from sqlalchemy import func, select
from regexsoc.services.export import to_csv
from regexsoc.db.service import record_audit
from regexsoc.security.audit import AuditAction
from regexsoc.db.activity_display import describe_activity
from regexsoc.db.playbooks import PLAYBOOKS, complete_step, playbook_state, select_playbook
from regexsoc.email_security.cases import linked_email_cases
from regexsoc.db import models
from regexsoc.db.incidents import (TRANSITIONS, add_incident_note, assign_incident,
    change_incident_status, create_incident, incident_activity, link_alert)
from regexsoc.security.rbac import has_permission
from regexsoc.web.csrf_middleware import current_token
from regexsoc.web.decorators import permission_required
from regexsoc.db import dashboard_queries as queries

bp = Blueprint("incidents", __name__, url_prefix="/incidents")

def _context(**extra):
    role = g.current_user.role
    return {"active": "incidents", "can_view_rules": has_permission(role, "view_rules"),
            "can_manage_rules": has_permission(role, "manage_rules"),
            "can_upload_logs": has_permission(role, "upload_logs"),
            "can_update_alert_status": has_permission(role, "update_alert_status"),
            "can_view_incidents": has_permission(role, "view_incidents"),
            "can_manage_incidents": has_permission(role, "manage_incidents"),
            "new_alert_count": queries.notification_count(g.db),
            "csrf_token": current_token(session, current_app.config["SECRET_KEY"]), **extra}

@bp.get("")
@permission_required("view_incidents")
def list_incidents():
    try:
        page = max(1, min(int(request.args.get("page", "1")), 100000))
    except ValueError:
        page = 1
    query = select(models.Incident)
    status = request.args.get("status", "")
    if status in models.INCIDENT_STATUSES:
        query = query.where(models.Incident.status == status)
    total = g.db.scalar(select(func.count()).select_from(query.subquery())) or 0
    items = g.db.scalars(query.order_by(models.Incident.updated_at.desc(), models.Incident.id.desc())
                         .offset((page-1)*25).limit(25)).all()
    return render_template("dashboard/incidents.html", **_context(incidents=items, page=page,
        total=total, selected_status=status, statuses=models.INCIDENT_STATUSES))

@bp.get("/export.csv")
@permission_required("view_incidents")
def export_incidents():
    """Bounded, permission-gated CSV for analyst reporting; no raw evidence exported."""
    items = g.db.scalars(select(models.Incident).order_by(
        models.Incident.id.desc()).limit(1000)).all()
    rows = [{"id": item.id, "title": item.title, "severity": item.severity,
             "status": item.status, "owner": item.owner or "",
             "created_at": item.created_at, "updated_at": item.updated_at}
            for item in items]
    response = Response(to_csv(rows, fields=["id", "title", "severity", "status", "owner",
                                             "created_at", "updated_at"]), mimetype="text/csv")
    response.headers["Content-Disposition"] = 'attachment; filename="centralsoc-incidents.csv"'
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    record_audit(g.db, AuditAction.INCIDENTS_EXPORTED, g.current_user.username, "SUCCESS",
                 ip_address=request.remote_addr, detail={"rows": len(rows), "limit": 1000})
    return response


@bp.post("")
@permission_required("manage_incidents")
def create():
    try:
        item = create_incident(g.db, request.form.get("title", ""), request.form.get("description", ""),
              request.form.get("severity", "MEDIUM"), g.current_user.username)
        g.db.flush()
        flash("Incident created.")
        return redirect(url_for("incidents.detail", incident_id=item.id))
    except ValueError as exc:
        g.db.rollback()
        flash(str(exc))
        return redirect(url_for("incidents.list_incidents"))

@bp.get("/<int:incident_id>")
@permission_required("view_incidents")
def detail(incident_id):
    item = g.db.get(models.Incident, incident_id)
    if item is None:
        return "Incident not found", 404
    alerts = g.db.scalars(select(models.Alert).join(models.IncidentAlert,
        models.IncidentAlert.alert_id == models.Alert.id).where(
        models.IncidentAlert.incident_id == incident_id).order_by(models.Alert.id.desc())).all()
    playbook, completed_steps = playbook_state(g.db, incident_id)
    return render_template("dashboard/incident_detail.html", **_context(incident=item, alerts=alerts,
        playbooks=PLAYBOOKS, playbook=playbook, completed_steps=completed_steps,
        email_cases=linked_email_cases(g.db, incident_id),
        activity=[(entry, describe_activity(entry.action, entry.detail)) for entry in incident_activity(g.db, incident_id)], transitions=sorted(TRANSITIONS[item.status])))

@bp.post("/<int:incident_id>/<action>")
@permission_required("manage_incidents")
def modify(incident_id, action):
    if action not in {"status", "assign", "note", "link", "playbook", "step"}:
        return "Not found", 404
    try:
        actor = g.current_user.username
        if action == "status":
            change_incident_status(g.db, incident_id, request.form.get("status", ""), actor,
                resolution=request.form.get("resolution") or None)
        elif action == "assign":
            assign_incident(g.db, incident_id, request.form.get("owner", ""), actor)
        elif action == "note":
            add_incident_note(g.db, incident_id, request.form.get("note", ""), actor)
        elif action == "link":
            link_alert(g.db, incident_id, request.form.get("alert_id", ""), actor)
        elif action == "playbook":
            select_playbook(g.db, incident_id, request.form.get("playbook", ""), actor)
        else:
            complete_step(g.db, incident_id, request.form.get("step", ""), actor)
        flash("Incident updated.")
    except (LookupError, ValueError) as exc:
        g.db.rollback()
        flash(str(exc))
    return redirect(url_for("incidents.detail", incident_id=incident_id))
