"""Append-only audit trail. Never pass secrets in ``details``: keys that look sensitive are
redacted defensively before persistence."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.orm import Session

from aegis.models import AuditLog

_SENSITIVE = ("password", "token", "secret", "code", "key", "cookie", "authorization")


def _redact(details: dict[str, Any]) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    for key, value in details.items():
        if any(marker in key.lower() for marker in _SENSITIVE):
            clean[key] = "[redacted]"
        elif isinstance(value, dict):
            clean[key] = _redact(value)
        else:
            clean[key] = value
    return clean


def record(
    db: Session,
    *,
    action: str,
    resource_type: str,
    resource_id: str | uuid.UUID | None = None,
    actor_id: uuid.UUID | None = None,
    actor_email: str | None = None,
    outcome: str = "success",
    ip_address: str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    entry = AuditLog(
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        actor_id=actor_id,
        actor_email=actor_email,
        outcome=outcome,
        ip_address=ip_address,
        details=_redact(details or {}),
    )
    db.add(entry)
    return entry
