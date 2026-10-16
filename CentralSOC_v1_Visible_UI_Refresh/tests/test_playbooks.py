"""Manual playbooks require explicit selection and persist audit-linked progress."""
import pytest
from sqlalchemy import select
from regexsoc.db import models
from regexsoc.db.incidents import create_incident
from regexsoc.db.playbooks import PLAYBOOKS, complete_step, playbook_state, select_playbook
from regexsoc.db.session import make_engine, init_db, session_scope
from regexsoc.security.audit import AuditAction


def _database():
    engine = make_engine('sqlite:///:memory:')
    init_db(engine)
    with session_scope(engine) as session:
        incident = create_incident(session, 'Test', '', 'HIGH', 'analyst')
        ident = incident.id
    return engine, ident


def test_playbook_progress_and_idempotence():
    engine, ident = _database()
    with session_scope(engine) as session:
        assert playbook_state(session, ident) == (None, set())
        with pytest.raises(ValueError):
            complete_step(session, ident, 'triage', 'analyst')
        select_playbook(session, ident, 'brute_force', 'analyst')
        assert complete_step(session, ident, 'triage', 'analyst')
        assert not complete_step(session, ident, 'triage', 'analyst')
    with session_scope(engine) as session:
        pb, done = playbook_state(session, ident)
        assert pb.key == 'brute_force' and done == {'triage'}
        assert len(session.scalars(select(models.AuditLog).where(
            models.AuditLog.action == AuditAction.PLAYBOOK_STEP_COMPLETED)).all()) == 1


def test_playbook_switch_resets_progress_and_validates_steps():
    engine, ident = _database()
    with session_scope(engine) as session:
        select_playbook(session, ident, 'brute_force', 'analyst')
        complete_step(session, ident, 'triage', 'analyst')
        with pytest.raises(ValueError):
            complete_step(session, ident, 'unknown', 'analyst')
        with pytest.raises(ValueError):
            select_playbook(session, ident, 'fake', 'analyst')
        select_playbook(session, ident, 'phishing', 'analyst')
        assert playbook_state(session, ident)[1] == set()
        assert len(PLAYBOOKS) >= 4


def test_playbook_transaction_rollback():
    engine, ident = _database()
    with pytest.raises(RuntimeError):
        with session_scope(engine) as session:
            select_playbook(session, ident, 'phishing', 'analyst')
            complete_step(session, ident, 'triage', 'analyst')
            raise RuntimeError('rollback')
    with session_scope(engine) as session:
        assert playbook_state(session, ident) == (None, set())


def test_playbook_missing_incident():
    engine, _ = _database()
    with session_scope(engine) as session:
        with pytest.raises(LookupError):
            select_playbook(session, 9999, 'phishing', 'analyst')
