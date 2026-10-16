"""Framework-light checks for permissions and incident Jinja templates."""
from pathlib import Path
from jinja2 import Environment
from regexsoc.security.rbac import has_permission

TEMPLATES = Path(__file__).resolve().parents[1] / 'regexsoc/web/templates'

def test_incident_access_roles():
    assert has_permission('VIEWER', 'view_incidents')
    assert not has_permission('VIEWER', 'manage_incidents')
    assert has_permission('ANALYST', 'manage_incidents')
    assert has_permission('ADMIN', 'manage_incidents')
    assert not has_permission('UNKNOWN', 'view_incidents')

def test_all_templates_parse():
    for path in TEMPLATES.rglob('*.html'):
        Environment().parse(path.read_text(encoding='utf-8'))

def test_incident_posts_csrf_and_escapes():
    for filename in ('incidents.html', 'incident_detail.html'):
        contents = (TEMPLATES / 'dashboard' / filename).read_text(encoding='utf-8')
        assert 'csrf_token' in contents
        assert '|safe' not in contents
