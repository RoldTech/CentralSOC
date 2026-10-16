"""Incident lifecycle services; authorization belongs to the server-side route boundary.

All write operations are transaction-bound. Call within session_scope or the Flask
request transaction. Notes reside in the existing append-only-in-workflow audit trail.
"""
from sqlalchemy import select
from sqlalchemy.orm import Session
from regexsoc.db import models
from regexsoc.db.service import record_audit
from regexsoc.security.audit import AuditAction, clean_text

TRANSITIONS = {
    "Open": {"Investigating", "Closed"},
    "Investigating": {"Contained", "Resolved", "Closed"},
    "Contained": {"Investigating", "Resolved"},
    "Resolved": {"Investigating", "Closed"},
    "Closed": {"Investigating"},
}


def _required(value: str, field: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > maximum:
        raise ValueError(f"{field} must contain 1 to {maximum} characters")
    return clean_text(value.strip(), maximum)


def _incident(session: Session, incident_id: int) -> models.Incident:
    item = session.get(models.Incident, incident_id)
    if item is None:
        raise LookupError(f"incident {incident_id} not found")
    return item


def create_incident(session: Session, title: str, description: str, severity: str, actor: str,
                    *, owner: str | None = None) -> models.Incident:
    if severity not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        raise ValueError("invalid severity")
    if not isinstance(description, str) or len(description) > 4000:
        raise ValueError("description exceeds 4000 characters")
    item = models.Incident(title=_required(title, "title", 200),
                           description=clean_text(description, 4000), severity=severity,
                           created_by=_required(actor, "actor", 80),
                           owner=_required(owner, "owner", 80) if owner is not None else None)
    session.add(item)
    session.flush()
    record_audit(session, AuditAction.INCIDENT_CREATED, actor, "SUCCESS",
                 resource=f"incident:{item.id}", detail={"severity": severity, "title": item.title})
    return item


def change_incident_status(session: Session, incident_id: int, status: str, actor: str,
                           *, resolution: str | None = None) -> models.Incident:
    item = _incident(session, incident_id)
    if status not in TRANSITIONS.get(item.status, set()):
        raise ValueError(f"invalid transition from {item.status!r} to {status!r}")
    if status in ("Resolved", "Closed") and not (resolution or item.resolution):
        raise ValueError("resolution is required when resolving or closing an incident")
    if resolution is not None:
        item.resolution = _required(resolution, "resolution", 2000)
    prior = item.status
    item.status = status
    item.updated_at = models.utcnow()
    record_audit(session, AuditAction.INCIDENT_UPDATED, actor, "SUCCESS",
                 resource=f"incident:{item.id}", detail={"from": prior, "to": status})
    return item


def assign_incident(session: Session, incident_id: int, owner: str, actor: str) -> models.Incident:
    item = _incident(session, incident_id)
    previous = item.owner
    item.owner = _required(owner, "owner", 80)
    item.updated_at = models.utcnow()
    record_audit(session, AuditAction.INCIDENT_UPDATED, actor, "SUCCESS",
                 resource=f"incident:{item.id}", detail={"owner_from": previous, "owner_to": item.owner})
    return item


def link_alert(session: Session, incident_id: int, alert_id: str, actor: str) -> models.IncidentAlert:
    item = _incident(session, incident_id)
    alert = session.scalar(select(models.Alert).where(models.Alert.alert_id == alert_id))
    if alert is None:
        raise LookupError(f"alert {alert_id} not found")
    existing = session.scalar(select(models.IncidentAlert).where(
        models.IncidentAlert.incident_id == item.id, models.IncidentAlert.alert_id == alert.id))
    if existing is not None:
        return existing
    relation = models.IncidentAlert(incident_id=item.id, alert_id=alert.id,
                                    linked_by=_required(actor, "actor", 80))
    session.add(relation)
    item.updated_at = models.utcnow()
    session.flush()
    record_audit(session, AuditAction.INCIDENT_ALERT_LINKED, actor, "SUCCESS",
                 resource=f"incident:{item.id}", detail={"alert_id": alert.alert_id})
    return relation


def add_incident_note(session: Session, incident_id: int, note: str, actor: str):
    item = _incident(session, incident_id)
    content = _required(note, "note", 1000)
    item.updated_at = models.utcnow()
    return record_audit(session, AuditAction.INCIDENT_NOTE_ADDED, actor, "SUCCESS",
                        resource=f"incident:{item.id}", detail={"note": content})


def incident_activity(session: Session, incident_id: int, limit: int = 100):
    _incident(session, incident_id)
    if not 1 <= limit <= 500:
        raise ValueError("limit must be 1 to 500")
    return list(session.scalars(select(models.AuditLog).where(
        models.AuditLog.resource == f"incident:{incident_id}",
        models.AuditLog.result == "SUCCESS").order_by(models.AuditLog.id.desc()).limit(limit)))
