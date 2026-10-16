import io
import urllib.error
import pytest
from datetime import datetime
from test_web_app import app, login
from regexsoc.db import models
from regexsoc.db.session import session_scope
from regexsoc.services import investigation


def seed_history(app):
    with session_scope(app.extensions['regexsoc_engine']) as db:
        f=models.LogFile(original_name='history.log',stored_name='history',size_bytes=1,sha256='a'*64,uploaded_by='admin')
        db.add(f);db.flush()
        for n,ip in enumerate(('198.51.100.23','198.51.100.230')):
            db.add(models.Alert(alert_id=f'HIST-{n}',log_file_id=f.id,rule_id='TEST',rule_name=f'History {n}',timestamp=datetime(2024,1,1),severity='HIGH',risk_score=85,reason='Test',recommended_response='Review',source_ip=ip))
        e=models.Event(log_file_id=f.id,seq=1,timestamp=datetime(2024,1,1),source_ip='198.51.100.23',destination_ip='203.0.113.10',event_type='network',source_format='test',raw_log='test',prev_hash='a'*64,hash='b'*64)
        db.add(e);db.flush()
        db.add(models.IOC(log_file_id=f.id,event_id=e.id,ioc_type='IP',value='198.51.100.23',context='test',rule_id='TEST'))


def test_ip_history_includes_unreviewed_events_iocs_and_exact_match(app):
    seed_history(app); c=app.test_client();login(c,'admin')
    r=c.get('/security-memory?q=198.51.100.23')
    assert r.status_code==200
    assert b'HIST-0' in r.data and b'HIST-1' not in r.data
    assert b'Not reviewed' in r.data and b'Related events' in r.data and b'Extracted indicators' in r.data
    assert b'No matching security memories' not in r.data
    assert b'HIST-0' not in c.get('/security-memory?q=198.51.100.23&reviewed=1').data
    assert b'Related events' in c.get('/security-memory?q=203.0.113.10').data
    assert b'No matching security memories' in c.get('/security-memory?q=192.0.2.99').data
    assert b'HIST-0' not in c.get('/security-memory?q=%25').data


def test_ai_configuration_checks_normalize_without_exposing_key(monkeypatch):
    monkeypatch.setenv('CENTRALSOC_AI_ENABLED',' true ')
    monkeypatch.setenv('OPENAI_API_KEY',' hidden-secret ')
    monkeypatch.setenv('CENTRALSOC_AI_MODEL',' test-model ')
    assert investigation.ai_enabled()
    assert 'hidden-secret' not in str(investigation.ai_status())
    monkeypatch.setenv('OPENAI_API_KEY','   ')
    assert not investigation.ai_enabled()


@pytest.mark.parametrize('code,match',[(400,'request rejected'),(401,'authentication failed'),(403,'access denied'),(404,'unavailable'),(429,'quota/billing'),(500,'service unavailable')])
def test_provider_errors_are_actionable_and_do_not_leak(monkeypatch,code,match):
    monkeypatch.setenv('OPENAI_API_KEY','test-only')
    class Opener:
        def open(self,*args,**kwargs):
            raise urllib.error.HTTPError('https://api.openai.com',code,'secret-provider-body',{},io.BytesIO(b'secret-provider-body'))
    monkeypatch.setattr(investigation.urllib.request,'build_opener',lambda *a:Opener())
    with pytest.raises(investigation.AIProviderError) as error:
        investigation.ask_ai({},'test-model')
    assert match in str(error.value) and 'secret-provider-body' not in str(error.value)


def test_ai_setup_is_visible_to_admin_and_key_not_rendered(app,monkeypatch):
    seed_history(app);monkeypatch.setenv('OPENAI_API_KEY','never-display-this-key')
    c=app.test_client();login(c,'admin')
    page=c.get('/alerts/1/investigation')
    assert page.status_code==200 and b'Server setup instructions' in page.data
    assert b'never-display-this-key' not in page.data
