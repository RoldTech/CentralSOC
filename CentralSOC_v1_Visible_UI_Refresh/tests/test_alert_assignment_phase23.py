"""Assignment workflow and persistence tests."""
import pytest
from sqlalchemy import select
from regexsoc.db import models
from regexsoc.db.session import make_engine, init_db, session_scope
from regexsoc.db.service import assign_alert, alert_activity
from regexsoc.db.alert_queue import build_alert_queue, normalize_alert_filters
from regexsoc.security.rbac import has_permission


def seeded():
    engine = make_engine('sqlite:///:memory:')
    init_db(engine)
    with session_scope(engine) as s:
        s.add_all([models.User(username='analyst', role='ANALYST', password_hash='x', is_active=True),
                   models.User(username='disabled', role='ANALYST', password_hash='x', is_active=False),
                   models.User(username='viewer', role='VIEWER', password_hash='x', is_active=True)])
        lf = models.LogFile(original_name='test.log', stored_name='file', size_bytes=1,
                            sha256='a'*64, uploaded_by='test')
        s.add(lf); s.flush()
        s.add(models.Alert(alert_id='ALERT-TEST', log_file_id=lf.id, rule_id='TEST', rule_name='Test',
                           severity='LOW', risk_score=10, reason='Test', recommended_response='Review'))
    return engine


def test_assign_and_unassign_with_audit():
    engine=seeded()
    with session_scope(engine) as s:
        assert assign_alert(s, 'ALERT-TEST', 'analyst', 'admin').assigned_to == 'analyst'
    with session_scope(engine) as s:
        assert s.scalar(select(models.Alert)).assigned_to == 'analyst'
        assert [e.action for e in alert_activity(s, 'ALERT-TEST')] == ['ALERT_ASSIGNED']
        assert assign_alert(s, 'ALERT-TEST', '', 'admin').assigned_to is None
    with session_scope(engine) as s:
        assert len(alert_activity(s, 'ALERT-TEST')) == 2
        assert s.scalar(select(models.Alert)).assigned_to is None


def test_reject_unknown_inactive_or_viewer():
    engine=seeded()
    with session_scope(engine) as s:
        for assignee in ('ghost', 'disabled', 'viewer'):
            with pytest.raises(ValueError): assign_alert(s, 'ALERT-TEST', assignee, 'admin')
        assert alert_activity(s, 'ALERT-TEST') == []


def test_rollback_and_owned_queue():
    engine=seeded()
    with pytest.raises(RuntimeError):
        with session_scope(engine) as s:
            assign_alert(s, 'ALERT-TEST', 'analyst', 'admin')
            raise RuntimeError('rollback')
    with session_scope(engine) as s:
        assert s.scalar(select(models.Alert)).assigned_to is None
        assert not alert_activity(s, 'ALERT-TEST')
        unassigned = normalize_alert_filters({'ownership':'unassigned'})
        mine = normalize_alert_filters({'ownership':'mine'})
        assert len(s.scalars(build_alert_queue(unassigned)).all()) == 1
        assert len(s.scalars(build_alert_queue(mine, current_username='analyst')).all()) == 0
        assign_alert(s, 'ALERT-TEST', 'analyst', 'admin')
        assert len(s.scalars(build_alert_queue(mine, current_username='analyst')).all()) == 1
        assert len(s.scalars(build_alert_queue(unassigned)).all()) == 0


def test_assignment_permission():
    assert has_permission('ADMIN', 'assign_alerts')
    assert has_permission('ANALYST', 'assign_alerts')
    assert not has_permission('VIEWER', 'assign_alerts')
