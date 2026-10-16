"""Phase 26: trustworthy acknowledgement metrics and permission-gated rendering."""
from datetime import datetime, timedelta
from pathlib import Path

from jinja2 import Environment

from regexsoc.db import models
from regexsoc.db.dashboard_queries import acknowledgement_metrics
from regexsoc.db.session import make_engine, init_db, session_scope


def _database():
    engine = make_engine('sqlite:///:memory:')
    init_db(engine)
    with session_scope(engine) as db:
        f = models.LogFile(original_name='sample.log', stored_name='sample', size_bytes=1,
                           sha256='c' * 64, uploaded_by='test')
        db.add(f)
        db.flush()
        start = datetime(2026, 1, 1, 12)
        for number, status, duration in [(1, 'New', None), (2, 'Investigating', 300),
                                         (3, 'Resolved', 900), (4, 'New', -30)]:
            db.add(models.Alert(alert_id=f'PH26-{number}', log_file_id=f.id, rule_id='TEST',
                                rule_name='Test', timestamp=start, severity='LOW', risk_score=10,
                                reason='Synthetic', recommended_response='Review', status=status,
                                acknowledged_at=start + timedelta(seconds=duration) if duration is not None else None,
                                acknowledged_by='analyst' if duration is not None else None))
    return engine


def test_dashboard_metric_definitions():
    engine = _database()
    with session_scope(engine) as db:
        metrics = acknowledgement_metrics(db)
        assert metrics == {'acknowledged': 3, 'pending': 1,
                           'mean_time_to_ack_seconds': 600.0, 'sample_size': 2}


def test_dashboard_empty_metrics_do_not_claim_zero_response_time():
    engine = make_engine('sqlite:///:memory:')
    init_db(engine)
    with session_scope(engine) as db:
        result = acknowledgement_metrics(db)
        assert result['mean_time_to_ack_seconds'] is None
        assert result['sample_size'] == 0


def test_dashboard_acknowledgement_is_permission_gated_and_labeled():
    root = Path(__file__).resolve().parents[1] / 'regexsoc/web'
    route = (root / 'routes/dashboard.py').read_text(encoding='utf-8')
    template = (root / 'templates/dashboard/overview.html').read_text(encoding='utf-8')
    assert 'acknowledgement=q.acknowledgement_metrics(g.db) if has_permission(g.current_user.role, "view_alerts") else None' in route
    assert '{% if acknowledgement is not none %}' in template
    assert 'if acknowledgement.mean_time_to_ack_seconds is not none' in template
    assert 'Valid timing samples' in template
    assert 'All-time records' in template
    Environment().parse(template)
