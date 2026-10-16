"""Phase 21: only known indicators, bounded, cross-file related-event leads."""
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from regexsoc.db.models import Base, LogFile, Event, Alert
from regexsoc.db.dashboard_queries import investigation_context


def test_related_leads_require_known_indicators_and_other_file():
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        for i in range(2):
            db.add(LogFile(original_name=f'f{i}.log', stored_name=str(i)*32, size_bytes=10, sha256=str(i)*64, uploaded_by='test'))
        db.flush()
        def event(file_id, seq, ip, user):
            return Event(log_file_id=file_id, seq=seq, source_ip=ip, username=user,
                         timestamp=datetime(2026, 10, 15), event_type='AUTH', severity='LOW',
                         source_format='syslog', raw_log='synthetic', prev_hash='a'*64, hash='b'*64)
        db.add_all([event(1, 1, '192.0.2.1', 'alice'),
                    event(2, 1, '192.0.2.1', 'bob'), event(2, 2, '198.51.100.1', 'alice'),
                    event(2, 3, '198.51.100.1', 'charlie')])
        db.flush()
        alert = Alert(log_file_id=1, alert_id='A-1', rule_id='R1', rule_name='Test',
                      source_ip='192.0.2.1', username='alice', severity='HIGH', risk_score=75,
                      reason='synthetic', recommended_response='review')
        db.add(alert)
        db.flush()
        result = investigation_context(db, alert)
        assert {e.seq for e in result['related_events']} == {1, 2}
        assert all(e.log_file_id == 2 for e in result['related_events'])
        assert len(investigation_context(db, alert, limit=1)['related_events']) == 1
        assert len(investigation_context(db, alert, limit=999)['related_events']) == 2
        alert.source_ip = None
        alert.username = None
        assert investigation_context(db, alert)['related_events'] == []
