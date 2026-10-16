from regexsoc.security.rbac import ROLES, has_permission, ASSIGNABLE_ROLES
from regexsoc.db.models import User

def test_tiered_soc_permissions():
    assert set(('SOC_L1','SOC_L2','SOC_L3','SOC_MANAGER')) <= set(ROLES)
    assert has_permission('SOC_L1','update_alert_status')
    assert not has_permission('SOC_L1','manage_incidents')
    assert has_permission('SOC_L2','manage_incidents')
    assert not has_permission('SOC_L2','manage_rules')
    assert has_permission('SOC_L3','manage_rules')
    assert has_permission('SOC_MANAGER','assign_alerts')
    assert not has_permission('SOC_MANAGER','manage_users')
    assert has_permission('ADMIN','manage_users')
    assert not has_permission('SOC_L1','assign_alerts')
    assert 'SOC_L1' in ASSIGNABLE_ROLES
    assert 'VIEWER' not in ASSIGNABLE_ROLES

def test_user_role_size():
    assert User.__table__.c.role.type.length >= len('SOC_MANAGER')
