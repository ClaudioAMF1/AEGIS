"""Security response: a closed catalogue of administrative actions with preview, explicit
approval, audit, verifiable result and reversal where technically possible.

There is deliberately no generic "run command on host" action. Host isolation is a *request*
delivered to lab agents, which acknowledge it; the bundled agent records the request and
simulates isolation, it never alters firewall rules on its own.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis.config import get_settings
from aegis.db import utcnow
from aegis.models import (
    Agent,
    Alert,
    AlertStatus,
    AuthSession,
    DetectionRule,
    Endpoint,
    Incident,
    IncidentStatus,
    Investigation,
    ResponseAction,
    ResponseStatus,
    Severity,
    User,
)
from aegis.security import sessions


class ResponseError(ValueError):
    pass


@dataclass(frozen=True)
class ActionSpec:
    target_type: str
    description: str
    reversible: bool
    server_side: bool  # executed by the API on approval (vs. delivered to an agent)


CATALOGUE: dict[str, ActionSpec] = {
    "request_investigation": ActionSpec(
        "incident", "Move the incident to 'investigating' and log the request.", False, True
    ),
    "raise_incident_severity": ActionSpec(
        "incident", "Raise the incident severity to a given level.", True, True
    ),
    "disable_rule": ActionSpec("rule", "Disable a noisy or faulty detection rule.", True, True),
    "revoke_user_sessions": ActionSpec(
        "user", "Revoke every active AEGIS session of a platform user.", False, True
    ),
    "isolate_host_lab": ActionSpec(
        "endpoint",
        "Request network isolation of a lab endpoint. Delivered to its agent on the next "
        "heartbeat; the agent acknowledges and reports the outcome.",
        True,
        False,
    ),
}


def _target_label(db: Session, target_type: str, target_id: str) -> str:
    if target_type == "incident":
        incident = db.get(Incident, uuid.UUID(target_id))
        if incident is None:
            raise ResponseError("incident not found")
        return f"INC-{incident.number:04d}"
    if target_type == "rule":
        rule = db.scalar(
            select(DetectionRule).where(
                DetectionRule.rule_id == target_id, DetectionRule.is_current.is_(True)
            )
        )
        if rule is None:
            raise ResponseError("rule not found")
        return rule.rule_id
    if target_type == "user":
        user = db.get(User, uuid.UUID(target_id))
        if user is None:
            raise ResponseError("user not found")
        return user.email
    if target_type == "endpoint":
        endpoint = db.get(Endpoint, uuid.UUID(target_id))
        if endpoint is None:
            raise ResponseError("endpoint not found")
        return endpoint.hostname
    raise ResponseError("unknown target type")


def preview(
    db: Session, action_type: str, target_id: str, parameters: dict[str, Any]
) -> dict[str, Any]:
    """Describe the impact before anything happens. Raises ResponseError for invalid scope."""
    spec = CATALOGUE.get(action_type)
    if spec is None:
        raise ResponseError(f"unknown action '{action_type}'")
    try:
        label = _target_label(db, spec.target_type, target_id)
    except ValueError as exc:
        raise ResponseError(str(exc) or "invalid target id") from exc
    impact: dict[str, Any] = {
        "target_label": label,
        "description": spec.description,
        "reversible": spec.reversible,
        "confirmation_text": label,
    }
    if action_type == "disable_rule":
        rule = db.scalar(
            select(DetectionRule).where(
                DetectionRule.rule_id == target_id, DetectionRule.is_current.is_(True)
            )
        )
        assert rule is not None
        if not rule.enabled:
            raise ResponseError("rule is already disabled")
        open_alerts = db.scalar(
            select(func.count())
            .select_from(Alert)
            .where(Alert.rule_id == target_id, Alert.status != AlertStatus.CLOSED.value)
        )
        impact["effects"] = [
            f"Rule '{rule.title}' stops evaluating new events.",
            f"{open_alerts} open alert(s) from this rule remain untouched.",
        ]
    elif action_type == "revoke_user_sessions":
        count = db.scalar(
            select(func.count())
            .select_from(AuthSession)
            .where(
                AuthSession.user_id == uuid.UUID(target_id),
                AuthSession.revoked_at.is_(None),
                AuthSession.expires_at > utcnow(),
            )
        )
        impact["effects"] = [f"{count} active session(s) will be revoked immediately."]
    elif action_type == "raise_incident_severity":
        level = parameters.get("severity")
        if level not in {s.value for s in Severity}:
            raise ResponseError("parameter 'severity' is required")
        incident = db.get(Incident, uuid.UUID(target_id))
        assert incident is not None
        if Severity(level).rank <= Severity(incident.severity).rank:
            raise ResponseError("new severity must be higher than the current one")
        impact["effects"] = [f"Severity {incident.severity} → {level}."]
    elif action_type == "request_investigation":
        incident = db.get(Incident, uuid.UUID(target_id))
        assert incident is not None
        if incident.status != IncidentStatus.NEW.value:
            raise ResponseError("only new incidents can be moved to investigation")
        impact["effects"] = ["Incident status new → investigating."]
    elif action_type == "isolate_host_lab":
        endpoint = db.get(Endpoint, uuid.UUID(target_id))
        assert endpoint is not None
        if not (endpoint.is_synthetic or "lab" in endpoint.tags):
            raise ResponseError(
                "isolation is only allowed for endpoints tagged 'lab' (authorised scope)"
            )
        if endpoint.isolation_state not in {"none", "released"}:
            raise ResponseError(f"endpoint isolation state is '{endpoint.isolation_state}'")
        agents = db.scalar(
            select(func.count()).select_from(Agent).where(Agent.endpoint_id == endpoint.id)
        )
        impact["effects"] = [
            f"Isolation request delivered to {agents} agent(s) of {endpoint.hostname}.",
            "The agent acknowledges on its next heartbeat; the bundled agent simulates "
            "isolation and does not modify firewall rules.",
            "Reversal sends a release request.",
        ]
    return impact


def execute(db: Session, action: ResponseAction, actor: User) -> None:
    """Run a server-side action. Agent-delivered actions stay 'approved' until acknowledged."""
    spec = CATALOGUE[action.action_type]
    handlers: dict[str, Callable[[], dict[str, Any]]] = {
        "request_investigation": lambda: _set_incident(db, action, actor, status="investigating"),
        "raise_incident_severity": lambda: _set_incident(
            db,
            action,
            actor,
            severity=str(action.impact_preview.get("parameters", {}).get("severity")),
        ),
        "disable_rule": lambda: _toggle_rule(db, action.target_id, enabled=False),
        "revoke_user_sessions": lambda: {
            "sessions_revoked": sessions.revoke_all_for_user(db, uuid.UUID(action.target_id))
        },
    }
    if not spec.server_side:
        endpoint = db.get(Endpoint, uuid.UUID(action.target_id))
        if endpoint is not None:
            endpoint.isolation_state = "requested"
        action.result = {"delivery": "pending agent acknowledgement"}
        return
    action.result = handlers[action.action_type]()
    action.status = ResponseStatus.EXECUTED.value
    action.executed_at = utcnow()


def revert(db: Session, action: ResponseAction, actor: User) -> None:
    if action.action_type == "disable_rule":
        action.result = {**action.result, "revert": _toggle_rule(db, action.target_id, True)}
    elif action.action_type == "raise_incident_severity":
        previous = action.result.get("previous", {}).get("severity")
        action.result = {
            **action.result,
            "revert": _set_incident(db, action, actor, severity=str(previous)),
        }
    elif action.action_type == "isolate_host_lab":
        endpoint = db.get(Endpoint, uuid.UUID(action.target_id))
        if endpoint is not None:
            endpoint.isolation_state = "release_requested"
        action.result = {**action.result, "revert": "release request delivered to agent"}
    else:
        raise ResponseError("this action cannot be reverted")
    action.status = ResponseStatus.REVERTED.value
    action.reverted_at = utcnow()


def _toggle_rule(db: Session, rule_id: str, enabled: bool) -> dict[str, Any]:
    rule = db.scalar(
        select(DetectionRule).where(
            DetectionRule.rule_id == rule_id, DetectionRule.is_current.is_(True)
        )
    )
    if rule is None:
        raise ResponseError("rule not found")
    previous = rule.enabled
    rule.enabled = enabled
    rule.updated_at = utcnow()
    return {"rule_id": rule_id, "enabled": enabled, "previous": {"enabled": previous}}


def _set_incident(
    db: Session,
    action: ResponseAction,
    actor: User,
    status: str | None = None,
    severity: str | None = None,
) -> dict[str, Any]:
    incident = db.get(Incident, uuid.UUID(action.target_id))
    if incident is None:
        raise ResponseError("incident not found")
    previous = {"status": incident.status, "severity": incident.severity}
    if status:
        incident.status = status
        incident.first_triaged_at = incident.first_triaged_at or utcnow()
    if severity:
        incident.severity = severity
    incident.updated_at = utcnow()
    db.add(
        Investigation(
            incident_id=incident.id,
            entry_type="action",
            author_id=actor.id,
            author_name=actor.display_name,
            body=f"Response action '{action.action_type}' executed.",
            changes={"action_id": str(action.id), "previous": previous},
        )
    )
    return {
        "incident": str(incident.id),
        "previous": previous,
        "current": {"status": incident.status, "severity": incident.severity},
    }


def can_self_approve() -> bool:
    return get_settings().response_allow_self_approval
