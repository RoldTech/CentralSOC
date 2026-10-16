from types import SimpleNamespace
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from regexsoc.db.models import Base, Incident, EmailCaseIncident, AuditLog
from regexsoc.email_security.cases import save_case, link_case_incident, linked_incidents, linked_email_cases


def test_case_incident_link_idempotent_and_audited():
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    parsed = SimpleNamespace(headers=SimpleNamespace(subject='Phishing', from_=[]))
    verdict = SimpleNamespace(classification='SUSPICIOUS', score=55)
    with Session(engine) as db:
        case = save_case(db, b'synthetic eml', parsed, verdict, analyst='analyst')
        incident = Incident(title='Suspicious email', description='', severity='MEDIUM', status='Open', created_by='analyst')
        db.add(incident)
        db.flush()
        first = link_case_incident(db, case.id, incident.id, analyst='analyst')
        second = link_case_incident(db, case.id, incident.id, analyst='analyst')
        assert first.id == second.id
        assert len(linked_incidents(db, case.id)) == 1
        assert len(linked_email_cases(db, incident.id)) == 1
        assert db.query(EmailCaseIncident).count() == 1
        assert db.query(AuditLog).filter(AuditLog.action == 'EMAIL_CASE_INCIDENT_LINKED').count() == 1
        db.commit()


def test_invalid_id_or_rollback_does_not_persist_link():
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        with pytest.raises(ValueError):
            link_case_incident(db, 999, 888, analyst='analyst')
        assert db.scalar(select(EmailCaseIncident)) is None
