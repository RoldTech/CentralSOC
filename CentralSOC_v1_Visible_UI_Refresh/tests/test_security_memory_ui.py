from test_web_app import app, login
from regexsoc.db.session import session_scope
from regexsoc.db import models
from regexsoc.db.service import set_alert_verdict
from datetime import datetime


def test_memory_requires_login(app):
    assert app.test_client().get('/security-memory').status_code in (302, 401)


def test_verdict_becomes_searchable_memory_and_triage_counts(app):
    with session_scope(app.extensions['regexsoc_engine']) as s:
        source = models.LogFile(original_name='test.log', stored_name='memory-test', size_bytes=1, sha256='e'*64, uploaded_by='admin')
        s.add(source); s.flush()
        s.add(models.Alert(alert_id='MEM-1', log_file_id=source.id, rule_id='TEST', rule_name='Memory detection', timestamp=datetime(2026,1,1), severity='HIGH', risk_score=90, reason='Evidence', recommended_response='Review', source_ip='203.0.113.42'))
        s.flush()
        set_alert_verdict(s, 'MEM-1', 'FALSE_POSITIVE', 'Approved test scanner', 'admin')
    c = app.test_client(); login(c, 'admin')
    page = c.get('/security-memory?q=203.0.113.42')
    assert page.status_code == 200
    assert b'Approved test scanner' in page.data and b'FALSE_POSITIVE' in page.data
    assert b'No matching security memories' in c.get('/security-memory?q=nonexistent').data
    page = c.get('/alerts')
    assert page.status_code == 200 and b'High Risk' in page.data and b'Awaiting Verdict' in page.data
    assert b'RegexSOC' not in page.data
