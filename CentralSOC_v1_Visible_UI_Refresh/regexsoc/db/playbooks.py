"""Manual, auditable incident response checklists. Never executes containment actions."""
import json
from dataclasses import dataclass
from sqlalchemy import select
from sqlalchemy.orm import Session
from regexsoc.db import models
from regexsoc.db.service import record_audit
from regexsoc.security.audit import AuditAction

@dataclass(frozen=True)
class Playbook:
    key: str
    title: str
    trigger: str
    steps: tuple[tuple[str, str], ...]

PLAYBOOKS = {
    p.key: p for p in (
        Playbook('brute_force', 'Brute-force investigation', 'Repeated authentication failures from one source or against an account', (
            ('triage', 'Confirm scope, affected accounts, source IPs and timestamps'),
            ('evidence', 'Preserve authentication logs and related alert evidence'),
            ('validate', 'Check whether any login succeeded and assess false positives'),
            ('contain', 'Recommend authorized account or network containment; record approvals'),
            ('recover', 'Verify access and monitoring are restored'),
            ('close', 'Document outcome and lessons learned'),
        )),
        Playbook('phishing', 'Phishing email investigation', 'Suspicious email or credential-harvesting indicators', (
            ('triage', 'Identify recipients and reported user activity'),
            ('evidence', 'Preserve email headers, URLs and authentication results'),
            ('validate', 'Examine suspicious content without opening unsafe links'),
            ('contain', 'Recommend approved mail quarantine or account protection'),
            ('recover', 'Verify relevant accounts and mail controls'),
            ('close', 'Record verdict, impact and lessons learned'),
        )),
        Playbook('account_compromise', 'Suspected account compromise', 'Unexpected successful sign-in or privileged account activity', (
            ('triage', 'Identify the affected identity and suspicious sessions'),
            ('evidence', 'Preserve authentication and session evidence'),
            ('validate', 'Correlate host, source IP and timing before making a determination'),
            ('contain', 'Seek authorization before revoking sessions or resetting credentials'),
            ('recover', 'Verify authorized access and detection coverage'),
            ('close', 'Document root cause and corrective actions'),
        )),
        Playbook('malicious_ip', 'Suspicious network communication', 'Traffic to a known or suspected malicious indicator', (
            ('triage', 'Identify hosts, destination and telemetry source'),
            ('evidence', 'Preserve DNS, firewall and proxy logs'),
            ('validate', 'Verify indicator provenance and intelligence freshness'),
            ('contain', 'Recommend approved network blocks or host isolation'),
            ('recover', 'Confirm network service and monitoring health'),
            ('close', 'Record indicator confidence and lessons learned'),
        )),
    )
}

def _entries(session: Session, incident_id: int):
    return list(session.scalars(select(models.AuditLog).where(
        models.AuditLog.resource == f'incident:{incident_id}',
        models.AuditLog.action.in_((AuditAction.PLAYBOOK_SELECTED, AuditAction.PLAYBOOK_STEP_COMPLETED)),
        models.AuditLog.result == 'SUCCESS').order_by(models.AuditLog.id)))

def playbook_state(session: Session, incident_id: int):
    if session.get(models.Incident, incident_id) is None:
        raise LookupError('incident not found')
    selected = None
    completed = set()
    for entry in _entries(session, incident_id):
        try:
            detail = json.loads(entry.detail or '{}')
        except (ValueError, TypeError):
            continue
        if entry.action == AuditAction.PLAYBOOK_SELECTED:
            selected = detail.get('playbook')
            completed.clear()
        elif detail.get('playbook') == selected:
            completed.add(detail.get('step'))
    return PLAYBOOKS.get(selected), completed

def select_playbook(session: Session, incident_id: int, key: str, actor: str):
    if session.get(models.Incident, incident_id) is None:
        raise LookupError('incident not found')
    if key not in PLAYBOOKS:
        raise ValueError('unknown playbook')
    current, _ = playbook_state(session, incident_id)
    if current and current.key == key:
        return current
    record_audit(session, AuditAction.PLAYBOOK_SELECTED, actor, 'SUCCESS',
                 resource=f'incident:{incident_id}', detail={'playbook': key})
    return PLAYBOOKS[key]

def complete_step(session: Session, incident_id: int, step: str, actor: str):
    playbook, done = playbook_state(session, incident_id)
    if playbook is None:
        raise ValueError('select a playbook first')
    if step not in {key for key, _ in playbook.steps}:
        raise ValueError('unknown playbook step')
    if step in done:
        return False
    record_audit(session, AuditAction.PLAYBOOK_STEP_COMPLETED, actor, 'SUCCESS',
                 resource=f'incident:{incident_id}', detail={'playbook': playbook.key, 'step': step})
    return True
