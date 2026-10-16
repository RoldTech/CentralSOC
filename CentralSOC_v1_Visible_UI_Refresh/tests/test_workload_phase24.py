"""Database-backed triage workload and permission isolation."""
from pathlib import Path
from jinja2 import Environment
from regexsoc.db.dashboard_queries import analyst_workload
from regexsoc.db.session import make_engine, init_db, session_scope
from regexsoc.db import models
from regexsoc.security.rbac import has_permission


def seeded():
    engine = make_engine('sqlite:///:memory:')
    init_db(engine)
    with session_scope(engine) as db:
        db.add_all([models.User(username=name, role='ANALYST', password_hash='x', is_active=True) for name in ('alice', 'bob')])
        db.flush()
        f = models.LogFile(original_name='t.log', stored_name='sample', size_bytes=1,
                           sha256='b'*64, uploaded_by='admin')
        db.add(f)
        db.flush()
        records = [
            ('A1', 'New', None, 70), ('A2', 'Investigating', 'alice', 90),
            ('A3', 'New', 'alice', 30), ('A4', 'Investigating', 'bob', 60),
            ('A5', 'Resolved', None, 99), ('A6', 'False Positive', 'alice', 88),
        ]
        for aid, status, owner, risk in records:
            db.add(models.Alert(alert_id=aid, log_file_id=f.id, rule_id='RULE', rule_name='Test',
                                severity='HIGH', risk_score=risk, reason='synthetic test',
                                recommended_response='review', status=status, assigned_to=owner))
    return engine


def test_empty_workload():
    engine = make_engine('sqlite:///:memory:')
    init_db(engine)
    with session_scope(engine) as db:
        result = analyst_workload(db)
        assert result == {'active': 0, 'new': 0, 'investigating': 0,
                          'unassigned': 0, 'analysts': []}


def test_workload_counts_only_active_alerts():
    engine = seeded()
    with session_scope(engine) as db:
        result = analyst_workload(db)
        assert result['active'] == 4
        assert result['unassigned'] == 1
        assert result['new'] == 2
        assert result['investigating'] == 2
        assert result['analysts'] == [
            {'username': 'alice', 'active_count': 2, 'highest_risk': 90},
            {'username': 'bob', 'active_count': 1, 'highest_risk': 60},
        ]
        assert len(analyst_workload(db, limit=1)['analysts']) == 1


def test_workload_overview_uses_rbac_gate():
    root = Path(__file__).resolve().parents[1] / 'regexsoc/web'
    route = (root / 'routes/dashboard.py').read_text(encoding='utf-8')
    template = (root / 'templates/dashboard/overview.html').read_text(encoding='utf-8')
    assert 'workload=q.analyst_workload(g.db) if has_permission(g.current_user.role, "view_alerts") else None' in route
    assert '{% if workload is not none %}' in template
    assert has_permission('ADMIN', 'view_alerts')
    assert not has_permission('VIEWER', 'assign_alerts')
    Environment().parse(template)
