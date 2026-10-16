"""Persistence services: ingest, integrity verification, alert workflow and audit logging.

Functions flush but never commit; wrap calls in ``session_scope`` so a failure rolls everything back.
All database access goes through the ORM (parameterized), never string-built SQL.
"""

import logging
import os
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from regexsoc import config
from regexsoc.db import models
from regexsoc.models import Severity
from regexsoc.security.rbac import ASSIGNABLE_ROLES
from regexsoc.security.audit import RESULTS, AuditAction, clean_text, format_detail
from regexsoc.security.files import sanitize_filename
from regexsoc.security.integrity import (
    IntegrityReport, event_hash, sha256_file, sha256_text, to_naive_utc, verify_chain,
)
from regexsoc.services.analyzer import Analyzer

logger = logging.getLogger(__name__)
STATUSES = models.ALERT_STATUSES


# --------------------------------------------------------------------------- audit
def record_audit(session: Session, action: str, user: str | None, result: str, *,
                 ip_address: str | None = None, resource: str | None = None, detail=None) -> models.AuditLog:
    """Write an audit entry. Inputs are sanitized: control chars stripped, secrets redacted."""
    if result not in RESULTS:
        raise ValueError(f"audit result must be one of {RESULTS}, got {result!r}")
    row = models.AuditLog(
        timestamp=models.utcnow(),
        username=clean_text(user or "anonymous", 80),
        action=clean_text(action, 50),
        ip_address=clean_text(ip_address, 45) if ip_address else None,
        result=result,
        resource=clean_text(resource, 200) if resource else None,
        detail=format_detail(detail),
    )
    session.add(row)
    session.flush()
    return row


def list_audit(session: Session, limit: int = 50) -> list[models.AuditLog]:
    return list(session.scalars(select(models.AuditLog).order_by(models.AuditLog.id.desc()).limit(limit)))


# --------------------------------------------------------------------------- ingest
@dataclass
class IngestResult:
    log_file: models.LogFile
    duplicate: bool
    events: int = 0
    detections: int = 0
    alerts: int = 0
    iocs: int = 0


def _store_copy(src: Path, upload_dir: Path) -> tuple[Path, str]:
    """Copy into the upload directory under a random name. Mode 'xb' refuses to overwrite anything."""
    upload_dir.mkdir(parents=True, exist_ok=True)
    stored_name = uuid.uuid4().hex + ".log"
    dest = upload_dir / stored_name
    with open(src, "rb") as fin, open(dest, "xb") as fout:
        shutil.copyfileobj(fin, fout)
    return dest, stored_name


def _discard(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError as exc:
        logger.warning("could not remove temporary copy %s: %s", path, exc)


def _make_read_only(path: Path) -> None:
    try:
        os.chmod(path, 0o440)
    except OSError as exc:
        logger.warning("could not make %s read-only: %s", path, exc)


def ingest_file(session: Session, path: str | Path, *, uploaded_by: str, upload_dir: str | Path | None = None,
                analyzer: Analyzer | None = None, ip_address: str | None = None,
                original_name: str | None = None) -> IngestResult:
    """Store a read-only copy, analyze it and persist events (hash-chained), detections, alerts and IOCs.

    The file is hashed *after* copying, so the recorded hash describes exactly what is stored.
    Re-ingesting identical content is idempotent and returns the existing record.
    """
    path = Path(path)
    analyzer = analyzer or Analyzer()
    upload_dir = Path(upload_dir) if upload_dir else config.upload_dir()
    size = path.stat().st_size
    if size > config.max_input_bytes():
        raise ValueError(f"{path.name} is {size} bytes; limit is {config.max_input_bytes()}")

    stored_path, stored_name = _store_copy(path, upload_dir)
    try:
        digest = sha256_file(stored_path)
        existing = session.scalar(select(models.LogFile).where(models.LogFile.sha256 == digest))
        if existing is not None:
            _discard(stored_path)
            record_audit(session, AuditAction.FILE_UPLOAD, uploaded_by, "SUCCESS", ip_address=ip_address,
                         resource=f"log_file:{existing.id}", detail=f"duplicate of existing file (sha256 {digest})")
            return IngestResult(existing, True, existing.event_count, 0, existing.alert_count, 0)

        extension = Path(original_name or path.name).suffix.lower()
        if extension in (".csv", ".json", ".jsonl"):
            result = analyzer.analyze_file(stored_path, original_name=original_name or path.name)
        else:
            result = analyzer.analyze_file(stored_path)
        log_file = models.LogFile(
            original_name=sanitize_filename(original_name or path.name), stored_name=stored_name,
            size_bytes=stored_path.stat().st_size, sha256=digest, uploaded_by=clean_text(uploaded_by, 80),
            uploaded_at=models.utcnow(), event_count=len(result.events), alert_count=len(result.alerts),
        )
        session.add(log_file)
        session.flush()

        key, prev, rows = config.integrity_key(), digest, []
        for ev in result.events:
            row = models.Event(
                log_file_id=log_file.id, seq=ev.id, timestamp=to_naive_utc(ev.timestamp),
                source_ip=ev.source_ip, destination_ip=ev.destination_ip, source_port=ev.source_port,
                destination_port=ev.destination_port, protocol=ev.protocol, username=ev.username,
                auth_status=ev.auth_status, http_method=ev.http_method, http_path=ev.http_path,
                http_status=ev.http_status, user_agent=ev.user_agent, host=ev.host,
                request_params=ev.request_params, event_type=ev.event_type, severity=ev.severity,
                source_format=ev.source_format, line_number=ev.line_number,
                raw_log=ev.raw_log.replace("\x00", "\ufffd"),  # NUL bytes are not portable in text columns
            )
            row.prev_hash = prev
            row.hash = prev = event_hash(prev, row.seq, row, key)
            rows.append(row)
        session.add_all(rows)
        session.flush()
        event_pk = {row.seq: row.id for row in rows}

        for d in result.detections:
            session.add(models.Detection(
                log_file_id=log_file.id, rule_id=d.rule_id, rule_name=d.rule_name, category=d.category,
                severity=d.severity, risk_score=d.risk_score, source_ip=d.source_ip, username=d.username,
                event_type=d.event_type, timestamp=to_naive_utc(d.timestamp), reason=d.reason,
                evidence=d.evidence, event_seqs=d.event_ids[:200]))

        seen_ids: set[str] = set()
        for a in result.alerts:
            alert_id = "ALERT-" + sha256_text(f"{digest}|{a.alert_id}")[:10].upper()
            while alert_id in seen_ids:  # defensive: never violate the unique constraint
                alert_id = "ALERT-" + sha256_text(alert_id + "x")[:10].upper()
            seen_ids.add(alert_id)
            session.add(models.Alert(
                alert_id=alert_id, log_file_id=log_file.id, timestamp=to_naive_utc(a.timestamp),
                rule_id=a.rule_id, rule_name=a.rule_name, source_ip=a.source_ip, username=a.username,
                event_type=a.event_type, severity=a.severity, risk_score=a.risk_score, reason=a.reason,
                evidence=a.evidence, recommended_response=a.recommended_response,
                event_seqs=a.event_ids[:200], status="New"))

        for ioc in result.iocs:
            session.add(models.IOC(
                log_file_id=log_file.id, event_id=event_pk[ioc.event_id], ioc_type=ioc.ioc_type,
                value=ioc.value[:1024], timestamp=to_naive_utc(ioc.timestamp), context=ioc.context,
                rule_id=ioc.rule_id))
        session.flush()

        record_audit(session, AuditAction.FILE_UPLOAD, uploaded_by, "SUCCESS", ip_address=ip_address,
                     resource=f"log_file:{log_file.id}",
                     detail={"file": log_file.original_name, "sha256": digest, "events": len(result.events),
                             "alerts": len(result.alerts)})
    except BaseException:
        _discard(stored_path)
        raise
    _make_read_only(stored_path)
    return IngestResult(log_file, False, len(result.events), len(result.detections),
                        len(result.alerts), len(result.iocs))


# --------------------------------------------------------------------------- integrity
def verify_log_file(session: Session, log_file_id: int, *, upload_dir: str | Path | None = None,
                    user: str = "system", ip_address: str | None = None) -> IntegrityReport:
    """Compare the stored file's current hash with the original and verify the event hash chain."""
    log_file = session.get(models.LogFile, log_file_id)
    if log_file is None:
        raise LookupError(f"log file {log_file_id} not found")
    stored = Path(upload_dir) if upload_dir else config.upload_dir()
    stored = stored / log_file.stored_name
    if stored.exists():
        current = sha256_file(stored)
        file_status = "OK" if current == log_file.sha256 else "TAMPERED"
    else:
        current, file_status = None, "MISSING"

    rows = session.scalars(
        select(models.Event).where(models.Event.log_file_id == log_file_id).order_by(models.Event.seq)
    ).all()
    chain = verify_chain(log_file.sha256, rows, expected_count=log_file.event_count, key=config.integrity_key())
    report = IntegrityReport(log_file_id, log_file.sha256, current, file_status, chain)
    record_audit(session, AuditAction.INTEGRITY_CHECK, user, "SUCCESS" if report.ok else "FAILURE",
                 ip_address=ip_address, resource=f"log_file:{log_file_id}", detail=report.to_dict())
    return report


# --------------------------------------------------------------------------- alerts
def parse_status(text: str) -> str:
    """Accept 'investigating', 'false-positive', 'False Positive'... and return the canonical status."""
    wanted = text.strip().lower().replace("-", " ").replace("_", " ")
    for status in STATUSES:
        if status.lower() == wanted:
            return status
    raise ValueError(f"invalid status {text!r}; choose one of {', '.join(STATUSES)}")


def list_alerts(session: Session, status: str | None = None, min_severity: str | None = None,
                limit: int = 100) -> list[models.Alert]:
    query = select(models.Alert)
    if status:
        query = query.where(models.Alert.status == parse_status(status))
    if min_severity:
        floor = Severity.parse(min_severity).rank
        allowed = [s.value for s in Severity if s.rank >= floor]
        query = query.where(models.Alert.severity.in_(allowed))
    query = query.order_by(models.Alert.risk_score.desc(), models.Alert.id).limit(limit)
    return list(session.scalars(query))


def set_alert_verdict(session: Session, alert_id: str, verdict: str, reason: str, actor: str, *, ip_address=None):
    """Record a reviewed alert outcome; TN/FN belong to separately labelled datasets.

    The caller owns the transaction; an audit-write failure rolls back with the verdict.
    """
    if verdict not in ("TRUE_POSITIVE", "FALSE_POSITIVE", "INCONCLUSIVE"):
        raise ValueError("Unsupported alert verdict")
    reason = reason.strip()
    if not 5 <= len(reason) <= 1000:
        raise ValueError("A reason between 5 and 1000 characters is required")
    alert = session.scalar(select(models.Alert).where(models.Alert.alert_id == alert_id))
    if alert is None:
        raise ValueError("Alert not found")
    before = alert.analyst_verdict
    alert.analyst_verdict = verdict
    alert.verdict_reason = clean_text(reason, 1000)
    alert.verdict_by = actor
    alert.verdict_at = models.utcnow()
    record_audit(session, AuditAction.ALERT_VERDICT_SET, actor, "SUCCESS",
                 ip_address=ip_address, resource=f"alert:{alert_id}",
                 detail={"from": before, "to": verdict, "reason": alert.verdict_reason})
    return alert


def alert_activity(session: Session, alert_id: str, *, limit: int = 100) -> list[models.AuditLog]:
    """Return recent successful, persisted analyst activity for one alert."""
    if not 1 <= limit <= 500:
        raise ValueError("limit must be between 1 and 500")
    return list(session.scalars(
        select(models.AuditLog).where(
            models.AuditLog.resource == f"alert:{alert_id}",
            models.AuditLog.result == "SUCCESS",
            models.AuditLog.action.in_((AuditAction.ALERT_STATUS_CHANGED, AuditAction.ALERT_NOTE_ADDED, AuditAction.ALERT_ASSIGNED, AuditAction.ALERT_ACKNOWLEDGED, AuditAction.ALERT_VERDICT_SET)),
        ).order_by(models.AuditLog.id.desc()).limit(limit)
    ))


def add_alert_note(session: Session, alert_id: str, note: str, user: str, *,
                   ip_address: str | None = None) -> models.AuditLog:
    """Add an immutable-in-workflow note without replacing previous analyst observations.

    Audit entries are transactionally coupled to the alert update and sanitized before storage.
    This is an interim investigation history, not a tamper-proof evidence store.
    """
    if not isinstance(note, str) or not note.strip():
        raise ValueError("an analyst note must not be empty")
    if len(note) > 1000:
        raise ValueError("an analyst note must be 1000 characters or fewer")
    alert = session.scalar(select(models.Alert).where(models.Alert.alert_id == alert_id))
    if alert is None:
        raise LookupError(f"alert {alert_id} not found")
    cleaned = clean_text(note.strip(), 1000)
    alert.note = cleaned  # backward-compatible latest-note field
    alert.updated_by = clean_text(user, 80)
    alert.updated_at = models.utcnow()
    return record_audit(session, AuditAction.ALERT_NOTE_ADDED, user, "SUCCESS", ip_address=ip_address,
                        resource=f"alert:{alert_id}", detail={"note": cleaned})


def update_alert_status(session: Session, alert_id: str, new_status: str, user: str, *,
                        ip_address: str | None = None, note: str | None = None) -> models.Alert:
    """Change an alert's workflow status and record who did it in the audit log."""
    status = parse_status(new_status)
    alert = session.scalar(select(models.Alert).where(models.Alert.alert_id == alert_id))
    if alert is None:
        record_audit(session, AuditAction.ALERT_STATUS_CHANGED, user, "FAILURE", ip_address=ip_address,
                     resource=f"alert:{alert_id}", detail="alert not found")
        raise LookupError(f"alert {alert_id} not found")
    old = alert.status
    alert.status = status
    alert.updated_by = clean_text(user, 80)
    alert.updated_at = models.utcnow()
    session.flush()
    if note and note.strip():
        add_alert_note(session, alert_id, note, user, ip_address=ip_address)
    record_audit(session, AuditAction.ALERT_STATUS_CHANGED, user, "SUCCESS", ip_address=ip_address,
                 resource=f"alert:{alert_id}", detail={"from": old, "to": status})
    return alert


def assign_alert(session: Session, alert_id: str, assignee: str | None, actor: str, *,
                 ip_address: str | None = None) -> models.Alert:
    """Assign or unassign an alert to an existing active user. Never commits."""
    alert = session.scalar(select(models.Alert).where(models.Alert.alert_id == alert_id))
    if alert is None:
        raise LookupError("alert not found")
    username = (assignee or "").strip()
    if username:
        if len(username) > 80:
            raise ValueError("assignee is too long")
        user = session.scalar(select(models.User).where(
            models.User.username == username, models.User.is_active.is_(True)))
        if user is None or user.role not in ASSIGNABLE_ROLES:
            raise ValueError("assignee must be an active analyst or administrator")
    if alert.assigned_to == (username or None):
        return alert
    old = alert.assigned_to
    alert.assigned_to = username or None
    alert.updated_by = clean_text(actor, 80)
    alert.updated_at = models.utcnow()
    session.flush()
    record_audit(session, AuditAction.ALERT_ASSIGNED, actor, "SUCCESS",
                 ip_address=ip_address, resource=f"alert:{alert.alert_id}",
                 detail={"from": old, "to": alert.assigned_to})
    return alert


def acknowledge_alert(session: Session, alert_id: str, actor: str, *,
                      ip_address: str | None = None) -> models.Alert:
    """Record first acknowledgement once, without changing alert status or assignment.

    Caller must enforce permission. Timestamp is server-generated UTC; no commits here.
    The conditional UPDATE prevents concurrent requests overwriting the first acknowledgement.
    """
    from sqlalchemy import update
    if not actor or not actor.strip():
        raise ValueError("acknowledgement requires an authenticated actor")
    actor = clean_text(actor.strip(), 80)
    now = models.utcnow()
    changed = session.execute(update(models.Alert).where(
        models.Alert.alert_id == alert_id,
        models.Alert.acknowledged_at.is_(None)
    ).values(acknowledged_at=now, acknowledged_by=actor).execution_options(synchronize_session=False))
    alert = session.scalar(select(models.Alert).where(models.Alert.alert_id == alert_id))
    if alert is None:
        raise LookupError("alert not found")
    if changed.rowcount:
        session.expire(alert)
        record_audit(session, AuditAction.ALERT_ACKNOWLEDGED, actor, "SUCCESS",
                     ip_address=ip_address, resource=f"alert:{alert_id}",
                     detail={"acknowledged_at": now.isoformat()})
    return alert
