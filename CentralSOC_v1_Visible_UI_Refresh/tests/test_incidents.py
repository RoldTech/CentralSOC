"""Persistence and lifecycle regression tests for incident management."""
import pytest
from sqlalchemy import select
from regexsoc.db import models
from regexsoc.db.session import make_engine, init_db, session_scope
from regexsoc.db.incidents import (create_incident, change_incident_status, link_alert,
                                   add_incident_note, incident_activity, assign_incident)


def setup_db():
    engine = make_engine('sqlite:///:memory:')
    init_db(engine)
    with session_scope(engine) as session:
        f = models.LogFile(original_name='test.log', stored_name='test.log', size_bytes=1,
                           sha256='b'*64, uploaded_by='analyst')
        session.add(f)
        session.flush()
        session.add(models.Alert(alert_id='ALERT-INC', log_file_id=f.id, rule_id='AUTH',
                                 rule_name='Auth', severity='HIGH', risk_score=80,
                                 reason='Failed login', recommended_response='Review'))
    return engine


def test_create_link_and_record_activity():
    engine = setup_db()
    with session_scope(engine) as s:
        incident = create_incident(s, 'Brute force', 'Failed logins', 'HIGH', 'alice')
        link_alert(s, incident.id, 'ALERT-INC', 'alice')
        link_alert(s, incident.id, 'ALERT-INC', 'alice')  # idempotent
        add_incident_note(s, incident.id, 'Investigation started', 'alice')
        assign_incident(s, incident.id, 'bob', 'alice')
        incident_id = incident.id
    with session_scope(engine) as s:
        assert s.get(models.Incident, incident_id).owner == 'bob'
        assert len(s.scalars(select(models.IncidentAlert)).all()) == 1
        assert len(incident_activity(s, incident_id)) == 4


def test_status_transitions_require_resolution():
    engine = setup_db()
    with session_scope(engine) as s:
        obj = create_incident(s, 'Test', '', 'LOW', 'alice')
        with pytest.raises(ValueError):
            change_incident_status(s, obj.id, 'Resolved', 'alice')
        change_incident_status(s, obj.id, 'Investigating', 'alice')
        with pytest.raises(ValueError):
            change_incident_status(s, obj.id, 'Resolved', 'alice')
        change_incident_status(s, obj.id, 'Resolved', 'alice', resolution='No further activity')
        change_incident_status(s, obj.id, 'Closed', 'alice')


def test_validation_and_rollback():
    engine = setup_db()
    with pytest.raises(RuntimeError):
        with session_scope(engine) as s:
            incident = create_incident(s, 'Temporary', '', 'LOW', 'alice')
            link_alert(s, incident.id, 'ALERT-INC', 'alice')
            raise RuntimeError('abort transaction')
    with session_scope(engine) as s:
        assert s.scalars(select(models.Incident)).all() == []
        assert s.scalars(select(models.IncidentAlert)).all() == []
        assert s.scalars(select(models.AuditLog)).all() == []
        with pytest.raises(ValueError):
            create_incident(s, '', '', 'LOW', 'alice')
        with pytest.raises(LookupError):
            link_alert(s, 12345, 'ALERT-INC', 'alice')
