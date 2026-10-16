"""Bounded, metadata-only phishing case persistence; no raw emails are retained."""
from __future__ import annotations

import hashlib
from sqlalchemy import select
from regexsoc.db import models
from regexsoc.db.service import record_audit
from regexsoc.security.audit import clean_text

STATES = ('Open', 'Investigating', 'Escalated', 'Closed')


def save_case(db, raw: bytes, parsed, verdict, *, analyst: str, client_ip: str | None = None):
    """Store a fingerprint and minimal triage summary; intentionally discard raw message/body."""
    digest = hashlib.sha256(raw).hexdigest()
    row = models.EmailCase(
        sha256=digest,
        subject=clean_text(parsed.headers.subject or '(no subject)', 200),
        sender=clean_text(parsed.headers.from_[0].raw if parsed.headers.from_ else '(unknown)', 255),
        classification=clean_text(verdict.classification, 30),
        risk_score=int(verdict.score),
        status='Open',
        created_by=analyst,
    )
    db.add(row)
    db.flush()
    record_audit(db, 'EMAIL_CASE_CREATED', analyst, 'SUCCESS', resource=f'email_case:{row.id}',
                 ip_address=client_ip, detail={'sha256': digest, 'score': row.risk_score})
    return row


def update_case(db, row, *, status: str, note: str, analyst: str):
    if status not in STATES:
        raise ValueError('Invalid case status')
    if not note.strip() or len(note.strip()) > 1500:
        raise ValueError('A case note between 1 and 1500 characters is required')
    old = row.status
    row.status = status
    row.updated_at = models.utcnow()
    record_audit(db, 'EMAIL_CASE_UPDATED', analyst, 'SUCCESS', resource=f'email_case:{row.id}',
                 detail={'from': old, 'to': status, 'note': clean_text(note.strip(), 1500)})
    return row


def list_cases(db, *, limit: int = 50):
    return list(db.scalars(select(models.EmailCase).order_by(models.EmailCase.id.desc()).limit(min(max(limit, 1), 100))))


def link_case_incident(db, case_id: int, incident_id: int, *, analyst: str):
    """Link existing case to incident once; caller must enforce manage_incidents RBAC."""
    case = db.get(models.EmailCase, case_id)
    incident = db.get(models.Incident, incident_id)
    if case is None or incident is None:
        raise ValueError('Email case or incident does not exist')
    existing = db.scalar(select(models.EmailCaseIncident).where(
        models.EmailCaseIncident.email_case_id == case_id,
        models.EmailCaseIncident.incident_id == incident_id))
    if existing is not None:
        return existing
    link = models.EmailCaseIncident(email_case_id=case_id, incident_id=incident_id, linked_by=analyst)
    db.add(link)
    db.flush()
    record_audit(db, 'EMAIL_CASE_INCIDENT_LINKED', analyst, 'SUCCESS',
                 resource=f'email_case:{case_id}', detail={'incident_id': incident_id})
    return link


def linked_incidents(db, case_id: int):
    return list(db.scalars(select(models.Incident).join(
        models.EmailCaseIncident, models.EmailCaseIncident.incident_id == models.Incident.id
    ).where(models.EmailCaseIncident.email_case_id == case_id)
       .order_by(models.Incident.id.desc()).limit(50)))


def linked_email_cases(db, incident_id: int):
    return list(db.scalars(select(models.EmailCase).join(
        models.EmailCaseIncident, models.EmailCaseIncident.email_case_id == models.EmailCase.id
    ).where(models.EmailCaseIncident.incident_id == incident_id)
       .order_by(models.EmailCase.id.desc()).limit(50)))
