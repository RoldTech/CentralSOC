"""Regression tests for persistent alert investigation history."""
import pytest
from sqlalchemy import select
from regexsoc.db import models
from regexsoc.db.session import make_engine, init_db, session_scope
from regexsoc.db.service import add_alert_note, alert_activity, update_alert_status


def setup_alert():
    engine = make_engine('sqlite:///:memory:')
    init_db(engine)
    with session_scope(engine) as s:
        lf = models.LogFile(original_name='test.log', stored_name='test.log', size_bytes=1,
                            sha256='a'*64, uploaded_by='test')
        s.add(lf); s.flush()
        s.add(models.Alert(alert_id='ALERT-TEST',log_file_id=lf.id,rule_id='TEST',rule_name='Test',
                           severity='LOW',risk_score=10,reason='Test',recommended_response='Review'))
    return engine


def test_notes_append_not_overwrite_history():
    engine=setup_alert()
    with session_scope(engine) as s:
        add_alert_note(s,'ALERT-TEST','first finding','analyst')
        add_alert_note(s,'ALERT-TEST','second finding','analyst')
    with session_scope(engine) as s:
        activity=alert_activity(s,'ALERT-TEST')
        assert len(activity)==2
        assert 'second finding' in activity[0].detail
        assert 'first finding' in activity[1].detail
        assert s.scalar(select(models.Alert)).note=='second finding'


def test_status_and_note_record_separate_actions():
    engine=setup_alert()
    with session_scope(engine) as s:
        update_alert_status(s,'ALERT-TEST','investigating','analyst',note='triaging')
    with session_scope(engine) as s:
        assert {entry.action for entry in alert_activity(s,'ALERT-TEST')}=={
            'ALERT_STATUS_CHANGED','ALERT_NOTE_ADDED'}


def test_reject_empty_oversize_and_unknown_notes():
    engine=setup_alert()
    with session_scope(engine) as s:
        for note in ('  ','x'*1001):
            with pytest.raises(ValueError): add_alert_note(s,'ALERT-TEST',note,'analyst')
        with pytest.raises(LookupError): add_alert_note(s,'missing','hello','analyst')
        assert alert_activity(s,'ALERT-TEST')==[]


def test_failed_transaction_rolls_back_history():
    engine=setup_alert()
    with pytest.raises(RuntimeError):
        with session_scope(engine) as s:
            add_alert_note(s,'ALERT-TEST','should rollback','analyst')
            raise RuntimeError('abort')
    with session_scope(engine) as s:
        assert alert_activity(s,'ALERT-TEST')==[]
        assert s.scalar(select(models.Alert)).note is None
