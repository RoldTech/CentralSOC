"""Transactional local evidence orchestration; allowlisted action is snapshot only."""
from sqlalchemy import select, update
from regexsoc.db import models
from regexsoc.db.service import record_audit
from regexsoc.security.rbac import has_permission


def require(user, permission):
    if not user.is_active or not has_permission(user.role, permission):
        raise PermissionError('Permission denied')


def request_snapshot(db, incident_id, user, reason):
    require(user, 'manage_incidents')
    if db.get(models.Incident, incident_id) is None:
        raise LookupError('Incident not found')
    reason = reason.strip()
    if not 10 <= len(reason) <= 1000:
        raise ValueError('Provide a reason of 10–1000 characters')
    run = models.ResponseRun(incident_id=incident_id, requested_by=user.username, reason=reason)
    db.add(run); db.flush()
    record_audit(db, 'RESPONSE_REQUESTED', user.username, 'SUCCESS', resource=f'incident:{incident_id}', detail={'run_id':run.id, 'action':'snapshot'})
    return run


def transition(db, run, user, action):
    if action not in ('approve', 'reject', 'execute'):
        raise ValueError('Unknown action')
    require(user, 'view_audit_log' if action in ('approve','reject') else 'manage_incidents')
    expected, target = ('APPROVED','COMPLETED') if action == 'execute' else ('PENDING', 'APPROVED' if action == 'approve' else 'REJECTED')
    values = {'state':target}
    if action == 'approve':
        values['approved_by'] = user.username
    if action == 'execute':
        alerts = db.scalars(select(models.Alert).join(models.IncidentAlert,
            models.IncidentAlert.alert_id == models.Alert.id).where(models.IncidentAlert.incident_id == run.incident_id)
            .order_by(models.Alert.id).limit(101)).all()
        values['snapshot'] = {'action':'local_evidence_snapshot', 'limit':100, 'truncated':len(alerts)>100,
            'alerts':[{'id':a.id, 'alert_id':a.alert_id, 'risk_score':a.risk_score,
                       'status':a.status, 'verdict':a.analyst_verdict, 'log_file_id':a.log_file_id} for a in alerts[:100]],
            'executed_by':user.username, 'scope':'Alert metadata only; raw logs are not copied.'}
        values['completed_at'] = models.utcnow()
    result = db.execute(update(models.ResponseRun).where(models.ResponseRun.id == run.id,
        models.ResponseRun.state == expected).values(**values))
    if result.rowcount != 1:
        raise ValueError('Run already transitioned or is not in the required state')
    record_audit(db, 'RESPONSE_'+target, user.username, 'SUCCESS', resource=f'incident:{run.incident_id}',
                 detail={'run_id':run.id, 'action':action})
    db.flush()
