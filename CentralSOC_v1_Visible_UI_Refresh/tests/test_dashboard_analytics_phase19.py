"""Phase 19 charts must never substitute demo counts for stored records."""
from datetime import datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from regexsoc.db.models import Base, LogFile, Event, Alert, Detection
from regexsoc.db.dashboard_queries import analytics_overview


def test_empty_days_and_validation():
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        x = analytics_overview(db, days=7, now=datetime(2026, 10, 16))
        assert len(x['timeline']) == 7
        assert x['start'] == '2026-10-10'
        assert all(row['events'] == row['alerts'] == 0 for row in x['timeline'])
        assert sum(row['count'] for row in x['severity']) == 0
        assert analytics_overview(db, days=30, now=datetime(2026, 10, 16))['timeline'][0]['date'] == '2026-09-17'
        with pytest.raises(ValueError):
            analytics_overview(db, days=365)


def test_daily_bucket_and_range_exclusion():
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        log = LogFile(original_name='a.log', stored_name='a'*32, size_bytes=100, sha256='a'*64, uploaded_by='test')
        db.add(log)
        db.flush()
        common = dict(log_file_id=log.id, event_type='FAILED_LOGIN', severity='LOW', source_format='syslog', line_number=1, raw_log='synthetic', prev_hash='0'*64, hash='1'*64, seq=1)
        db.add(Event(**common, timestamp=datetime(2026, 10, 15, 13)))
        db.add(Event(**{**common, 'seq': 2}, timestamp=datetime(2026, 9, 1)))
        db.flush()
        result = analytics_overview(db, now=datetime(2026, 10, 16))
        assert result['timeline'][-2]['events'] == 1
        assert sum(v['events'] for v in result['timeline']) == 1
        assert result['authentication'][0]['count'] == 1
