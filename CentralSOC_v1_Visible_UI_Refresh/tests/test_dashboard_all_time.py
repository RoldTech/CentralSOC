"""All Time charts include historical evidence rather than only recent events."""
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from regexsoc.db.models import Base, LogFile, Event
from regexsoc.db.dashboard_queries import analytics_overview


def test_all_time_historical_monthly_buckets():
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        log = LogFile(original_name='old.log', stored_name='b'*32, size_bytes=20,
                      sha256='b'*64, uploaded_by='test')
        db.add(log)
        db.flush()
        base = dict(log_file_id=log.id, event_type='FAILED_LOGIN', severity='LOW',
                    source_format='syslog', line_number=1, raw_log='synthetic',
                    prev_hash='0'*64, hash='1'*64)
        db.add(Event(**base, seq=1, timestamp=datetime(2024, 3, 10)))
        db.add(Event(**base, seq=2, timestamp=datetime(2026, 3, 10)))
        db.flush()
        result = analytics_overview(db, days=None, now=datetime(2026, 10, 16))
        assert result['granularity'] == 'Monthly'
        assert result['start'] == '2024-03'
        assert result['end'] == '2026-03'
        assert len(result['timeline']) == 25
        assert sum(x['events'] for x in result['timeline']) == 2
        assert result['authentication'][0]['count'] == 2
        recent = analytics_overview(db, days=7, now=datetime(2026, 10, 16))
        assert sum(x['events'] for x in recent['timeline']) == 0


def test_all_time_empty_database():
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        result = analytics_overview(db, days=None, now=datetime(2026, 10, 16))
        assert result['timeline'] == [{'date': '2026-10', 'events': 0, 'alerts': 0}]
