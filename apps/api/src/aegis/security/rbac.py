"""Role-based access control.

Permissions are enforced exclusively on the server. The web client receives the permission
list only to hide controls the user cannot use; hiding is a UX nicety, never a barrier.
"""

from __future__ import annotations

from enum import StrEnum

from aegis.models import RoleName


class Permission(StrEnum):
    TELEMETRY_READ = "telemetry:read"
    ALERTS_TRIAGE = "alerts:triage"
    INCIDENTS_WRITE = "incidents:write"
    RULES_READ = "rules:read"
    RULES_MANAGE = "rules:manage"
    AGENTS_MANAGE = "agents:manage"
    INTEL_READ = "intel:read"
    INTEL_MANAGE = "intel:manage"
    ASSISTANT_USE = "assistant:use"
    REPORTS_READ = "reports:read"
    REPORTS_CREATE = "reports:create"
    RESPONSE_REQUEST = "response:request"
    RESPONSE_APPROVE = "response:approve"
    USERS_MANAGE = "users:manage"
    AUDIT_READ = "audit:read"
    DEMO_RUN = "demo:run"
    SETTINGS_MANAGE = "settings:manage"


_VIEWER = {
    Permission.TELEMETRY_READ,
    Permission.RULES_READ,
    Permission.INTEL_READ,
    Permission.REPORTS_READ,
}
_ANALYST = _VIEWER | {
    Permission.ALERTS_TRIAGE,
    Permission.INCIDENTS_WRITE,
    Permission.ASSISTANT_USE,
    Permission.REPORTS_CREATE,
    Permission.RESPONSE_REQUEST,
    Permission.DEMO_RUN,
}
_ADMIN = set(Permission)

ROLE_PERMISSIONS: dict[str, frozenset[Permission]] = {
    RoleName.VIEWER.value: frozenset(_VIEWER),
    RoleName.ANALYST.value: frozenset(_ANALYST),
    RoleName.ADMINISTRATOR.value: frozenset(_ADMIN),
}

ROLE_DESCRIPTIONS = {
    RoleName.ADMINISTRATOR.value: "Full control: users, rules, agents, response approval, audit.",
    RoleName.ANALYST.value: "Triage alerts, investigate incidents, use the assistant, request "
    "responses.",
    RoleName.VIEWER.value: "Read-only access to telemetry, detections, incidents and reports.",
}


def permissions_for(role: str) -> frozenset[Permission]:
    return ROLE_PERMISSIONS.get(role, frozenset())


def has_permission(role: str, permission: Permission) -> bool:
    return permission in permissions_for(role)
