"""Phase 27: vetted analyst decisions, audited changes and migration parity."""
from datetime import datetime
import pytest
from sqlalchemy import select
from regexsoc.db import models
from regexsoc.db.session import make_engine, init_db, session_scope
from regexsoc.db.service import set_alert_verdict, alert_activity
from regexsoc.services.export import to_csv


def seed():
    engine = make_engine('sqlite:///:memory:')
    init_db(engine)
    with session_scope(engine) as s:
        source=models.LogFile(original_name='demo.log',stored_name='demo',size_bytes=1,sha256='b'*64,uploaded_by='test')
        s.add(source);s.flush()
        s.add(models.Alert(alert_id='AL-27',log_file_id=source.id,rule_id='TEST',rule_name='Demo',
                           timestamp=datetime(2026,1,1),severity='HIGH',risk_score=75,
                           reason='Synthetic',recommended_response='Investigate'))
    return engine


def test_verdict_persists_with_audit():
    engine=seed()
    with session_scope(engine) as s:
        set_alert_verdict(s,'AL-27','FALSE_POSITIVE','Known approved security scan','analyst')
    with session_scope(engine) as s:
        a=s.scalar(select(models.Alert))
        assert a.analyst_verdict=='FALSE_POSITIVE'
        assert a.verdict_by=='analyst'
        assert a.verdict_reason=='Known approved security scan'
        assert [e.action for e in alert_activity(s,'AL-27')]==['ALERT_VERDICT_SET']


def test_invalid_verdict_and_reason_rejected():
    engine=seed()
    with session_scope(engine) as s:
        for verdict in ('TRUE_NEGATIVE','FALSE_NEGATIVE','HACKED',''):
            with pytest.raises(ValueError): set_alert_verdict(s,'AL-27',verdict,'Reason provided','analyst')
        with pytest.raises(ValueError): set_alert_verdict(s,'AL-27','TRUE_POSITIVE','x','analyst')


def test_verdict_rollback_also_rolls_back_audit():
    engine=seed()
    with pytest.raises(RuntimeError):
        with session_scope(engine) as s:
            set_alert_verdict(s,'AL-27','TRUE_POSITIVE','Verified exploitation evidence','analyst')
            raise RuntimeError('abort')
    with session_scope(engine) as s:
        assert s.scalar(select(models.Alert)).analyst_verdict is None
        assert not alert_activity(s,'AL-27')


def test_csv_handoff_formula_escaping():
    body=to_csv([{'username':'=HYPERLINK("evil")','reason':'-1+2'}],['username','reason'])
    assert "'=HYPERLINK" in body
    assert "'-1+2" in body
