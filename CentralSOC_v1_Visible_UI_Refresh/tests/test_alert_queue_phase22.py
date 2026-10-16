"""Phase 22 alert queue filtering tests without requiring Flask."""
from datetime import datetime
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from regexsoc.db.models import Base, Alert, LogFile
from regexsoc.db.alert_queue import normalize_alert_filters, build_alert_queue


def test_invalid_filters_do_not_change_enum_filters():
    f = normalize_alert_filters({'status': 'NOT_A_STATUS', 'severity': 'BAD', 'sort': 'random',
                                 'source_ip': 'a'*1000, 'username': 'b'*500, 'time_range': 'oops'})
    assert f['severity'] == f['status'] == ''
    assert f['sort'] == 'risk' and f['time_range'] == ''
    assert len(f['source_ip']) == 45 and len(f['username']) == 255


def test_queue_filters_username_ip_status_and_cutoff():
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(LogFile(original_name='sample', stored_name='a'*32, size_bytes=1,
                       sha256='b'*64, uploaded_by='test'))
        db.flush()
        for i, (username, ip, state, ts) in enumerate([
            ('alice', '192.0.2.1', 'New', datetime(2026, 10, 14)),
            ('bob', '192.0.2.1', 'New', datetime(2026, 10, 14)),
            ('alice', '198.51.100.1', 'Resolved', datetime(2026, 10, 14)),
            ('alice', '192.0.2.1', 'New', datetime(2025, 10, 14)),
        ]):
            db.add(Alert(log_file_id=1, alert_id=f'A{i}', timestamp=ts, rule_id='R1', rule_name='Test',
                         source_ip=ip, username=username, severity='HIGH', risk_score=80,
                         reason='synthetic', recommended_response='review', status=state))
        db.flush()
        filters = normalize_alert_filters({'username': 'alice', 'source_ip': '192.0.2.1', 'status': 'New'})
        found = db.scalars(build_alert_queue(filters, datetime(2026, 1, 1))).all()
        assert [row.alert_id for row in found] == ['A0']
        assert len(db.scalars(build_alert_queue(filters)).all()) == 2
