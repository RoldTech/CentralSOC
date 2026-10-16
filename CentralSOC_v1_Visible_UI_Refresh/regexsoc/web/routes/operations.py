"""Permission-gated response and investigation workspaces."""
from flask import Blueprint, abort, current_app, flash, g, redirect, render_template, request, url_for
from sqlalchemy import select
from regexsoc.db import models
from regexsoc.web.decorators import permission_required
from regexsoc.web.routes.dashboard import _ctx
from regexsoc.security.rbac import has_permission
from regexsoc.services.investigation import ai_enabled, ai_status, investigate
from regexsoc.services.response import request_snapshot, transition

bp = Blueprint('operations', __name__)

@bp.get('/alerts/<int:alert_id>/investigation')
@permission_required('view_alerts')
def investigations(alert_id):
    alert = g.db.get(models.Alert, alert_id)
    if not alert:
        abort(404)
    runs = g.db.scalars(select(models.InvestigationRun).where(models.InvestigationRun.alert_id == alert_id)
                       .order_by(models.InvestigationRun.id.desc()).limit(20)).all()
    return render_template('dashboard/investigations.html', **_ctx('alerts', alert=alert, runs=runs,
        ai_enabled=ai_enabled(), ai_status=ai_status(), can_configure=has_permission(g.current_user.role, 'configure_app'), can_investigate=has_permission(g.current_user.role, 'update_alert_status')))

@bp.post('/alerts/<int:alert_id>/investigation')
@permission_required('update_alert_status')
def create_investigation(alert_id):
    alert = g.db.get(models.Alert, alert_id)
    if not alert:
        abort(404)
    mode = request.form.get('mode','local')
    if mode == 'ai' and request.form.get('consent') != 'yes':
        return 'Confirm sending the listed metadata to the AI provider.', 400
    from regexsoc.security.ratelimit import FixedWindowLimiter
    limiter = current_app.extensions.setdefault('investigation_limiter', FixedWindowLimiter())
    if not limiter.allow(str(g.current_user.id), 10, 60):
        return 'Investigation rate limit exceeded; retry in one minute.', 429
    try:
        investigate(g.db, alert, g.current_user.username, mode)
    except ValueError as exc:
        return str(exc), 400
    return redirect(url_for('operations.investigations', alert_id=alert_id))

@bp.get('/incidents/<int:incident_id>/response-runs')
@permission_required('view_incidents')
def responses(incident_id):
    incident = g.db.get(models.Incident, incident_id)
    if not incident:
        abort(404)
    runs = g.db.scalars(select(models.ResponseRun).where(models.ResponseRun.incident_id == incident_id)
        .order_by(models.ResponseRun.id.desc()).limit(50)).all()
    return render_template('dashboard/response_runs.html', **_ctx('incidents', incident=incident, runs=runs,
        can_request=has_permission(g.current_user.role,'manage_incidents'),
        can_approve=has_permission(g.current_user.role,'view_audit_log')))

@bp.post('/incidents/<int:incident_id>/response-runs')
@permission_required('manage_incidents')
def create_response(incident_id):
    try:
        request_snapshot(g.db, incident_id, g.current_user, request.form.get('reason',''))
    except LookupError:
        abort(404)
    except ValueError as exc:
        return str(exc), 400
    return redirect(url_for('operations.responses', incident_id=incident_id))

@bp.post('/response-runs/<int:run_id>/<action>')
@permission_required('view_incidents')
def change_response(run_id, action):
    run = g.db.get(models.ResponseRun, run_id)
    if not run:
        abort(404)
    try:
        transition(g.db, run, g.current_user, action)
    except PermissionError:
        abort(403)
    except ValueError as exc:
        return str(exc), 409
    return redirect(url_for('operations.responses', incident_id=run.incident_id))
