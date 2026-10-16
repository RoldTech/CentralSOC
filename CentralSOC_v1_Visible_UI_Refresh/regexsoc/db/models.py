"""SQLAlchemy 2.0 ORM models.

Timestamps are stored as naive UTC. The schema is portable (SQLite now, PostgreSQL later): only
standard column types plus the generic JSON type are used.
"""

from datetime import UTC, datetime

from sqlalchemy import (
    JSON, CheckConstraint, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

ALERT_STATUSES = ("New", "Investigating", "Resolved", "False Positive")


def utcnow() -> datetime:
    """Current UTC time as a naive datetime (the storage convention)."""
    return datetime.now(UTC).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class LogFile(Base):
    """An ingested log file. ``sha256`` is the hash of the stored copy at ingest time."""

    __tablename__ = "log_files"

    id: Mapped[int] = mapped_column(primary_key=True)
    original_name: Mapped[str] = mapped_column(String(255))  # sanitized, display only
    stored_name: Mapped[str] = mapped_column(String(64), unique=True)  # random server-side name
    size_bytes: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    uploaded_by: Mapped[str] = mapped_column(String(80))
    uploaded_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    alert_count: Mapped[int] = mapped_column(Integer, default=0)


class Event(Base):
    """A normalized event plus its position in the file's hash chain."""

    __tablename__ = "events"
    __table_args__ = (UniqueConstraint("log_file_id", "seq", name="uq_events_file_seq"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    log_file_id: Mapped[int] = mapped_column(ForeignKey("log_files.id", ondelete="CASCADE"), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    timestamp: Mapped[datetime | None] = mapped_column(DateTime, index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45))
    source_port: Mapped[int | None] = mapped_column(Integer)
    destination_port: Mapped[int | None] = mapped_column(Integer, index=True)
    protocol: Mapped[str | None] = mapped_column(String(20))
    username: Mapped[str | None] = mapped_column(String(255), index=True)
    auth_status: Mapped[str | None] = mapped_column(String(10))
    http_method: Mapped[str | None] = mapped_column(String(16))
    http_path: Mapped[str | None] = mapped_column(Text)
    http_status: Mapped[int | None] = mapped_column(Integer)
    user_agent: Mapped[str | None] = mapped_column(Text)
    host: Mapped[str | None] = mapped_column(String(255))
    request_params: Mapped[dict] = mapped_column(JSON, default=dict)
    event_type: Mapped[str] = mapped_column(String(30), index=True)
    severity: Mapped[str] = mapped_column(String(10), default="LOW")
    source_format: Mapped[str] = mapped_column(String(20))
    line_number: Mapped[int] = mapped_column(Integer, default=0)
    raw_log: Mapped[str] = mapped_column(Text)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


class Detection(Base):
    """Every rule firing (including low-score ones); alerts are the subset above the threshold."""

    __tablename__ = "detections"

    id: Mapped[int] = mapped_column(primary_key=True)
    log_file_id: Mapped[int] = mapped_column(ForeignKey("log_files.id", ondelete="CASCADE"), index=True)
    rule_id: Mapped[str] = mapped_column(String(20), index=True)
    rule_name: Mapped[str] = mapped_column(String(100))
    category: Mapped[str] = mapped_column(String(40), index=True)
    severity: Mapped[str] = mapped_column(String(10), index=True)
    risk_score: Mapped[int] = mapped_column(Integer)
    source_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    username: Mapped[str | None] = mapped_column(String(255))
    event_type: Mapped[str | None] = mapped_column(String(30))
    timestamp: Mapped[datetime | None] = mapped_column(DateTime)
    reason: Mapped[str] = mapped_column(Text)
    evidence: Mapped[list] = mapped_column(JSON, default=list)
    event_seqs: Mapped[list] = mapped_column(JSON, default=list)


class Alert(Base):
    """An analyst-facing alert with a workflow status."""

    __tablename__ = "alerts"
    __table_args__ = (
        CheckConstraint("status IN ('New','Investigating','Resolved','False Positive')", name="ck_alert_status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    alert_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    log_file_id: Mapped[int] = mapped_column(ForeignKey("log_files.id", ondelete="CASCADE"), index=True)
    timestamp: Mapped[datetime | None] = mapped_column(DateTime)
    rule_id: Mapped[str] = mapped_column(String(20), index=True)
    rule_name: Mapped[str] = mapped_column(String(100))
    source_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    username: Mapped[str | None] = mapped_column(String(255))
    event_type: Mapped[str | None] = mapped_column(String(30))
    severity: Mapped[str] = mapped_column(String(10), index=True)
    risk_score: Mapped[int] = mapped_column(Integer)
    reason: Mapped[str] = mapped_column(Text)
    evidence: Mapped[list] = mapped_column(JSON, default=list)
    recommended_response: Mapped[str] = mapped_column(Text)
    event_seqs: Mapped[list] = mapped_column(JSON, default=list)  # the Event.seq values behind this alert
    status: Mapped[str] = mapped_column(String(20), default="New", index=True)
    assigned_to: Mapped[str | None] = mapped_column(String(80), ForeignKey("users.username", ondelete="RESTRICT"), index=True)
    analyst_verdict: Mapped[str | None] = mapped_column(String(30), nullable=True, index=True)
    verdict_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    verdict_by: Mapped[str | None] = mapped_column(String(80), nullable=True)
    verdict_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    acknowledged_by: Mapped[str | None] = mapped_column(String(80), nullable=True)
    updated_by: Mapped[str | None] = mapped_column(String(80))
    updated_at: Mapped[datetime | None] = mapped_column(DateTime)
    note: Mapped[str | None] = mapped_column(Text)


class IOC(Base):
    """An extracted indicator of compromise with provenance."""

    __tablename__ = "iocs"

    id: Mapped[int] = mapped_column(primary_key=True)
    log_file_id: Mapped[int] = mapped_column(ForeignKey("log_files.id", ondelete="CASCADE"), index=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"), index=True)
    ioc_type: Mapped[str] = mapped_column(String(20), index=True)
    value: Mapped[str] = mapped_column(String(1024), index=True)
    timestamp: Mapped[datetime | None] = mapped_column(DateTime)
    context: Mapped[str] = mapped_column(Text)
    rule_id: Mapped[str] = mapped_column(String(20))


class AuditLog(Base):
    """Application audit trail. Never stores passwords, tokens or other secrets (see security.audit)."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    username: Mapped[str] = mapped_column(String(80), index=True)
    action: Mapped[str] = mapped_column(String(50), index=True)
    ip_address: Mapped[str | None] = mapped_column(String(45))
    result: Mapped[str] = mapped_column(String(10))
    resource: Mapped[str | None] = mapped_column(String(200))
    detail: Mapped[str | None] = mapped_column(Text)


class User(Base):
    """An application user."""

    __tablename__ = "users"
    __table_args__ = (CheckConstraint("role IN ('ADMIN','ANALYST','VIEWER','SOC_L1','SOC_L2','SOC_L3','SOC_MANAGER')", name="ck_user_role"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    email: Mapped[str | None] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="VIEWER")
    is_active: Mapped[bool] = mapped_column(default=True)
    mfa_enabled: Mapped[bool] = mapped_column(default=False)
    mfa_secret: Mapped[str | None] = mapped_column(String(64))  # only set once mfa_enabled is confirmed
    pending_mfa_secret: Mapped[str | None] = mapped_column(String(64))  # awaiting confirmation
    backup_codes_hash: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime)


class LoginAttempt(Base):
    """One row per login attempt, used for account lockout and security review."""

    __tablename__ = "login_attempts"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(80), index=True)
    ip_address: Mapped[str | None] = mapped_column(String(45))
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    success: Mapped[bool] = mapped_column()


INCIDENT_STATUSES = ("Open", "Investigating", "Contained", "Resolved", "Closed")


class Incident(Base):
    """Analyst-managed case. Containment is a recorded status, never an automated action."""

    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint("status IN ('Open','Investigating','Contained','Resolved','Closed')", name="ck_incident_status"),
        CheckConstraint("severity IN ('LOW','MEDIUM','HIGH','CRITICAL')", name="ck_incident_severity"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(10), default="LOW")
    status: Mapped[str] = mapped_column(String(20), default="Open", index=True)
    owner: Mapped[str | None] = mapped_column(String(80), index=True)
    created_by: Mapped[str] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    resolution: Mapped[str | None] = mapped_column(Text)


class IncidentAlert(Base):
    """Explicit many-to-many relationship retaining alert provenance."""

    __tablename__ = "incident_alerts"
    __table_args__ = (UniqueConstraint("incident_id", "alert_id", name="uq_incident_alert"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id", ondelete="RESTRICT"), index=True)
    linked_by: Mapped[str] = mapped_column(String(80))
    linked_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class EmailCase(Base):
    """Metadata-only analyst phishing case. Raw email/attachments are never persisted."""

    __tablename__ = "email_cases"
    __table_args__ = (
        CheckConstraint("status IN ('Open','Investigating','Escalated','Closed')", name="ck_email_case_status"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    subject: Mapped[str] = mapped_column(String(200))
    sender: Mapped[str] = mapped_column(String(255))
    classification: Mapped[str] = mapped_column(String(30))
    risk_score: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(20), default="Open", index=True)
    created_by: Mapped[str] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class EmailCaseIncident(Base):
    """Explicit, audited association between metadata-only email cases and incidents."""

    __tablename__ = "email_case_incidents"
    __table_args__ = (UniqueConstraint("email_case_id", "incident_id", name="uq_email_case_incident"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    email_case_id: Mapped[int] = mapped_column(ForeignKey("email_cases.id", ondelete="CASCADE"), index=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    linked_by: Mapped[str] = mapped_column(String(80))
    linked_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ResponseRun(Base):
    """Approved, locally executed evidence snapshot. No external containment connector."""
    __tablename__ = 'response_runs'
    __table_args__ = (CheckConstraint("state IN ('PENDING','APPROVED','COMPLETED','REJECTED')", name='ck_response_run_state'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey('incidents.id', ondelete='CASCADE'), index=True)
    state: Mapped[str] = mapped_column(String(20), default='PENDING')
    requested_by: Mapped[str] = mapped_column(String(80))
    approved_by: Mapped[str | None] = mapped_column(String(80))
    reason: Mapped[str] = mapped_column(Text)
    snapshot: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)


class InvestigationRun(Base):
    """Immutable application-level evidence bundle and advisory result per request."""
    __tablename__ = 'investigation_runs'
    id: Mapped[int] = mapped_column(primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey('alerts.id', ondelete='CASCADE'), index=True)
    requested_by: Mapped[str] = mapped_column(String(80))
    mode: Mapped[str] = mapped_column(String(20))
    state: Mapped[str] = mapped_column(String(20))
    model: Mapped[str | None] = mapped_column(String(120))
    evidence: Mapped[dict] = mapped_column(JSON)
    summary: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
