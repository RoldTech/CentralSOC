"""CentralSOC RBAC: exact, server-enforced permission sets.

Legacy ANALYST stays valid to preserve existing accounts.
"""
from __future__ import annotations

ROLES = ("VIEWER", "ANALYST", "SOC_L1", "SOC_L2", "SOC_L3", "SOC_MANAGER", "ADMIN")
ROLE_LABELS = {
    "VIEWER": "Read-only Analyst", "ANALYST": "Legacy SOC Analyst",
    "SOC_L1": "SOC Analyst L1", "SOC_L2": "SOC Analyst L2",
    "SOC_L3": "SOC Analyst L3", "SOC_MANAGER": "SOC Manager",
    "ADMIN": "Administrator",
}
_VIEW = {"view_events", "view_alerts", "view_iocs", "view_rules", "view_statistics", "view_incidents"}
_L1 = _VIEW | {"upload_logs", "update_alert_status", "search_iocs"}
_L2 = _L1 | {"manage_incidents"}
_L3 = _L2 | {"manage_rules"}
_MANAGER = _L2 | {"assign_alerts", "view_audit_log"}
_LEGACY = _L2 | {"assign_alerts"}
_ADMIN = _L3 | _MANAGER | {"manage_users", "configure_app"}
PERMISSIONS: dict[str, frozenset[str]] = {
    "VIEWER": frozenset(_VIEW), "ANALYST": frozenset(_LEGACY),
    "SOC_L1": frozenset(_L1), "SOC_L2": frozenset(_L2),
    "SOC_L3": frozenset(_L3), "SOC_MANAGER": frozenset(_MANAGER),
    "ADMIN": frozenset(_ADMIN),
}
ASSIGNABLE_ROLES = frozenset({"SOC_L1", "SOC_L2", "SOC_L3", "SOC_MANAGER", "ANALYST", "ADMIN"})

def is_valid_role(role: str) -> bool:
    return role in ROLES

def has_permission(role: str, permission: str) -> bool:
    return permission in PERMISSIONS.get(role, frozenset())

def permissions_for(role: str) -> frozenset[str]:
    return PERMISSIONS.get(role, frozenset())
