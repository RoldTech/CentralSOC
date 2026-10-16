"""Real database metrics, including permission-gated dashboard integration contract."""
from sqlalchemy import select
from regexsoc.db import models
from regexsoc.db.dashboard_queries import incident_overview, detection_overview
from regexsoc.db.session import make_engine, init_db, session_scope


def test_dashboard_empty_state_uses_zeros():
    engine = make_engine('sqlite:///:memory:')
    init_db(engine)
    with session_scope(engine) as session:
        assert incident_overview(session)['total'] == 0
        assert incident_overview(session)['active'] == 0
        assert incident_overview(session)['recent'] == []
        assert detection_overview(session) == {'matches': 0, 'rules_fired': 0}


def test_incident_metrics_are_persisted_and_grouped():
    engine = make_engine('sqlite:///:memory:')
    init_db(engine)
    with session_scope(engine) as session:
        session.add_all([
            models.Incident(title='Open issue', created_by='analyst', severity='HIGH', status='Open'),
            models.Incident(title='Working issue', created_by='analyst', severity='MEDIUM', status='Investigating'),
            models.Incident(title='Finished issue', created_by='analyst', severity='LOW', status='Closed'),
        ])
    with session_scope(engine) as session:
        metrics = incident_overview(session)
        assert metrics['total'] == 3
        assert metrics['active'] == 2
        assert metrics['by_status']['Closed'] == 1
        assert metrics['by_status']['Contained'] == 0
        assert len(metrics['recent']) == 3


def test_dashboard_template_hides_incident_section_for_unauthorized_role():
    from pathlib import Path
    from jinja2 import Environment
    template = Path(__file__).resolve().parents[1] / 'regexsoc/web/templates/dashboard/overview.html'
    text = template.read_text(encoding='utf-8')
    assert '{% if incident_stats is not none %}' in text
    assert 'incident_stats=q.incident_overview(g.db) if can_view_incidents else None' in (
        (Path(__file__).resolve().parents[1] / 'regexsoc/web/routes/dashboard.py').read_text()
    )
    Environment().parse(text)
