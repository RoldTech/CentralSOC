import pytest

from regexsoc.security.rbac import PERMISSIONS, ROLES, has_permission, is_valid_role, permissions_for


def test_viewer_is_read_only():
    for perm in ("upload_logs", "update_alert_status", "manage_users", "manage_rules", "view_audit_log"):
        assert not has_permission("VIEWER", perm)
    for perm in ("view_events", "view_alerts", "view_iocs", "view_statistics"):
        assert has_permission("VIEWER", perm)


def test_analyst_can_analyze_but_not_administer():
    for perm in ("upload_logs", "update_alert_status", "search_iocs", "view_events"):
        assert has_permission("ANALYST", perm)
    for perm in ("manage_users", "manage_rules", "view_audit_log"):
        assert not has_permission("ANALYST", perm)


def test_admin_has_every_permission_including_analyst_and_viewer():
    all_perms = set().union(*PERMISSIONS.values())
    assert all(has_permission("ADMIN", p) for p in all_perms)


@pytest.mark.parametrize("role", ["viewer", "Admin", "", "SUPERUSER", None])
def test_invalid_or_wrong_case_role_denied(role):
    assert not has_permission(role, "view_events")


def test_unknown_permission_is_denied_for_every_role():
    for role in ROLES:
        assert not has_permission(role, "delete_everything")


def test_is_valid_role():
    assert all(is_valid_role(r) for r in ROLES)
    assert not is_valid_role("viewer") and not is_valid_role("root")


def test_role_hierarchy_is_strictly_increasing():
    assert permissions_for("VIEWER") < permissions_for("ANALYST") < permissions_for("ADMIN")
