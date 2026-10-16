"""HTTP workflow from login/upload through memory, investigation and approved snapshot."""
import json
from sqlalchemy import select, func
from test_web_app import app, login, api_csrf_token, SAMPLE
from regexsoc.db import models
from regexsoc.db.session import session_scope
from regexsoc.services import investigation


def upload(client):
    with SAMPLE.open('rb') as f:
        r = client.post('/api/logs/upload', data={'file':(f,'ssh_auth.log')},
            headers={'X-CSRFToken':api_csrf_token(client)}, content_type='multipart/form-data')
    assert r.status_code == 201
    return client.get('/api/alerts?severity=critical').json['alerts'][0]


def post(client, path, **data):
    return client.post(path, data=data, headers={'X-CSRFToken':api_csrf_token(client)})


def test_end_to_end_memory_investigation_and_response(app):
    analyst=app.test_client(); login(analyst,'analyst')
    alert=upload(analyst); aid=alert['id']
    assert post(analyst,f'/alerts/{aid}/verdict',verdict='TRUE_POSITIVE',reason='Confirmed repeated failures in source evidence').status_code == 302
    assert b'TRUE_POSITIVE' in analyst.get('/security-memory').data
    assert post(analyst,f'/alerts/{aid}/investigation',mode='local').status_code == 302
    page=analyst.get(f'/alerts/{aid}/investigation')
    assert page.status_code == 200 and b'deterministic evidence brief' in page.data
    assert post(analyst,'/incidents',title='Workflow case',description='Integration test',severity='HIGH').status_code == 302
    with session_scope(app.extensions['regexsoc_engine']) as db:
        incident=db.scalar(select(models.Incident)); iid=incident.id
        alert_id=db.get(models.Alert,aid).alert_id
    assert post(analyst,f'/incidents/{iid}/link',alert_id=alert_id).status_code == 302
    assert post(analyst,f'/incidents/{iid}/response-runs',reason='Preserve the current incident evidence').status_code == 302
    with session_scope(app.extensions['regexsoc_engine']) as db:
        rid=db.scalar(select(models.ResponseRun.id))
    assert post(analyst,f'/response-runs/{rid}/execute').status_code == 409
    assert post(analyst,f'/response-runs/{rid}/approve').status_code == 403
    admin=app.test_client();login(admin,'admin')
    assert post(admin,f'/response-runs/{rid}/approve').status_code == 302
    assert post(analyst,f'/response-runs/{rid}/execute').status_code == 302
    assert post(analyst,f'/response-runs/{rid}/execute').status_code == 409
    assert analyst.get(f'/incidents/{iid}/response-runs').status_code == 200
    with session_scope(app.extensions['regexsoc_engine']) as db:
        run=db.get(models.ResponseRun,rid)
        assert run.state=='COMPLETED' and run.approved_by=='admin'
        assert run.snapshot['alerts'][0]['id']==aid
        assert db.scalar(select(func.count()).select_from(models.AuditLog).where(models.AuditLog.action=='RESPONSE_COMPLETED'))==1
        assert db.scalar(select(models.InvestigationRun)).evidence['events']


def test_readonly_csrf_and_missing_resources(app):
    admin=app.test_client();login(admin,'admin'); aid=upload(admin)['id']
    assert admin.post(f'/alerts/{aid}/investigation',data={'mode':'local'}).status_code==400
    viewer=app.test_client();login(viewer,'viewer')
    assert viewer.get(f'/alerts/{aid}/investigation').status_code==200
    assert post(viewer,f'/alerts/{aid}/investigation',mode='local').status_code==403
    assert post(viewer,'/incidents/1/response-runs',reason='Invalid role request').status_code==403
    assert admin.get('/alerts/999999/investigation').status_code==404
    assert app.test_client().get(f'/alerts/{aid}/investigation').status_code in (302,401)


def test_ai_opt_in_and_failure_are_persisted_without_secrets(app, monkeypatch):
    c=app.test_client();login(c,'admin');aid=upload(c)['id']
    monkeypatch.delenv('CENTRALSOC_AI_ENABLED',raising=False)
    assert post(c,f'/alerts/{aid}/investigation',mode='ai',consent='yes').status_code==400
    monkeypatch.setenv('CENTRALSOC_AI_ENABLED','1');monkeypatch.setenv('OPENAI_API_KEY','secret-key');monkeypatch.setenv('CENTRALSOC_AI_MODEL','test-model')
    assert post(c,f'/alerts/{aid}/investigation',mode='ai').status_code==400
    def fail(*args):raise TimeoutError('secret-key provider failure')
    monkeypatch.setattr(investigation,'ask_ai',fail)
    assert post(c,f'/alerts/{aid}/investigation',mode='ai',consent='yes').status_code==302
    with session_scope(app.extensions['regexsoc_engine']) as db:
        run=db.scalar(select(models.InvestigationRun))
        assert run.state=='FAILED' and 'secret-key' not in run.summary
        assert db.get(models.Alert,aid).analyst_verdict is None
    monkeypatch.setattr(investigation,'ask_ai',lambda b,m:'<script>bad()</script> Hypothesis only.')
    assert post(c,f'/alerts/{aid}/investigation',mode='ai',consent='yes').status_code==302
    assert b'&lt;script&gt;' in c.get(f'/alerts/{aid}/investigation').data


def test_provider_contract(monkeypatch):
    monkeypatch.setenv('OPENAI_API_KEY','test-only')
    class Response:
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def read(self,n):return json.dumps({'status':'completed','output':[{'type':'message','content':[{'type':'output_text','text':'Review alert:1'}]}]}).encode()
    class Opener:
        def open(self,req,timeout):
            payload=json.loads(req.data)
            assert req.full_url=='https://api.openai.com/v1/responses' and timeout==25
            assert payload['store'] is False and 'tools' not in payload
            assert payload['input']=='{"alert": {"reference": "alert:1"}}'
            return Response()
    monkeypatch.setattr(investigation.urllib.request,'build_opener',lambda *args:Opener())
    assert investigation.ask_ai({'alert':{'reference':'alert:1'}},'test-model')=='Review alert:1'


def test_rejected_run_cannot_execute(app):
    c=app.test_client();login(c,'admin')
    post(c,'/incidents',title='Rejected case',description='',severity='LOW')
    with session_scope(app.extensions['regexsoc_engine']) as db:iid=db.scalar(select(models.Incident.id))
    post(c,f'/incidents/{iid}/response-runs',reason='Preserve current case metadata')
    with session_scope(app.extensions['regexsoc_engine']) as db:rid=db.scalar(select(models.ResponseRun.id))
    assert post(c,f'/response-runs/{rid}/reject').status_code==302
    assert post(c,f'/response-runs/{rid}/execute').status_code==409
    assert post(c,f'/response-runs/{rid}/approve').status_code==409
