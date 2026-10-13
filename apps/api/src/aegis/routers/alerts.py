"""Alert queue and triage."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from aegis.db import utcnow
from aegis.models import (
    Alert,
    AlertDisposition,
    AlertEvent,
    AlertStatus,
    DetectionRule,
    Endpoint,
    Event,
    Incident,
    IncidentEvent,
    Investigation,
    Severity,
)
from aegis.routers.common import not_found, scope_clause
from aegis.schemas import AlertDetail, AlertOut, EventOut, IncidentOut, Page, RuleOut, Scope
from aegis.security.deps import DbSession, Principal, client_ip, require
from aegis.security.rbac import Permission
from aegis.services import audit
from aegis.services.alerting import next_incident_number

router = APIRouter(prefix="/alerts", tags=["alerts"])
Reader = Annotated[Principal, Depends(require(Permission.TELEMETRY_READ))]
Triager = Annotated[Principal, Depends(require(Permission.ALERTS_TRIAGE))]


def to_out(alert: Alert, hostnames: dict[uuid.UUID, str]) -> AlertOut:
    return AlertOut.model_validate(alert).model_copy(
        update={"hostname": hostnames.get(alert.endpoint_id)}
    )


def hostnames_for(db: DbSession, ids: set[uuid.UUID]) -> dict[uuid.UUID, str]:
    if not ids:
        return {}
    return dict(
        db.execute(select(Endpoint.id, Endpoint.hostname).where(Endpoint.id.in_(ids))).all()
    )


@router.get("", response_model=Page[AlertOut])
def list_alerts(
    _: Reader,
    db: DbSession,
    scope: Scope = Scope.LIVE,
    status_: Annotated[AlertStatus | None, Query(alias="status")] = None,
    severity: Severity | None = None,
    rule_id: str | None = None,
    endpoint_id: uuid.UUID | None = None,
    incident_id: uuid.UUID | None = None,
    unassigned: bool = False,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[AlertOut]:
    filters = [scope_clause(Alert.is_synthetic, scope)]
    if status_:
        filters.append(Alert.status == status_.value)
    if severity:
        filters.append(Alert.severity == severity.value)
    if rule_id:
        filters.append(Alert.rule_id == rule_id)
    if endpoint_id:
        filters.append(Alert.endpoint_id == endpoint_id)
    if incident_id:
        filters.append(Alert.incident_id == incident_id)
    if unassigned:
        filters.append(Alert.incident_id.is_(None))
    total = db.scalar(select(func.count()).select_from(Alert).where(*filters))
    rows = db.scalars(
        select(Alert)
        .where(*filters)
        .order_by(Alert.last_event_at.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    names = hostnames_for(db, {a.endpoint_id for a in rows})
    return Page(items=[to_out(a, names) for a in rows], total=total)


@router.get("/{alert_id}", response_model=AlertDetail)
def get_alert(alert_id: uuid.UUID, _: Reader, db: DbSession) -> AlertDetail:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise not_found("alert")
    events = db.scalars(
        select(Event)
        .join(AlertEvent, AlertEvent.event_id == Event.id)
        .where(AlertEvent.alert_id == alert_id)
        .order_by(Event.occurred_at)
        .limit(500)
    ).all()
    rule = db.scalar(
        select(DetectionRule).where(
            DetectionRule.rule_id == alert.rule_id, DetectionRule.version == alert.rule_version
        )
    )
    base = to_out(alert, hostnames_for(db, {alert.endpoint_id}))
    return AlertDetail(
        **base.model_dump(),
        events=[EventOut.model_validate(e) for e in events],
        rule=RuleOut.model_validate(rule) if rule else None,
    )


class AlertTriage(BaseModel):
    status: AlertStatus | None = None
    disposition: AlertDisposition | None = None
    note: Annotated[str, Field(max_length=2000)] | None = None


@router.patch("/{alert_id}", response_model=AlertOut)
def triage_alert(
    alert_id: uuid.UUID, body: AlertTriage, principal: Triager, request: Request, db: DbSession
) -> AlertOut:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise not_found("alert")
    changes: dict[str, object] = {}
    if body.status and body.status.value != alert.status:
        changes["status"] = [alert.status, body.status.value]
        alert.status = body.status.value
    if body.disposition and body.disposition.value != alert.disposition:
        changes["disposition"] = [alert.disposition, body.disposition.value]
        alert.disposition = body.disposition.value
        if body.disposition == AlertDisposition.FALSE_POSITIVE:
            alert.status = AlertStatus.CLOSED.value
    if changes and alert.triaged_at is None:
        alert.triaged_at = utcnow()
        alert.triaged_by = principal.id
    if alert.incident_id and (changes or body.note):
        db.add(
            Investigation(
                incident_id=alert.incident_id,
                entry_type="change",
                author_id=principal.id,
                author_name=principal.user.display_name,
                body=body.note or f"Alert '{alert.title}' triaged.",
                changes={"alert_id": str(alert.id), **changes},
            )
        )
    audit.record(
        db,
        action="alert.triage",
        resource_type="alert",
        resource_id=alert.id,
        actor_id=principal.id,
        actor_email=principal.user.email,
        ip_address=client_ip(request),
        details={"changes": changes},
    )
    db.commit()
    return to_out(alert, hostnames_for(db, {alert.endpoint_id}))


class EscalateIn(BaseModel):
    alert_ids: list[uuid.UUID] = Field(min_length=1, max_length=200)
    title: Annotated[str, Field(min_length=3, max_length=255)] | None = None
    incident_id: uuid.UUID | None = None


@router.post("/escalate", response_model=IncidentOut, status_code=status.HTTP_201_CREATED)
def escalate(
    body: EscalateIn,
    principal: Annotated[Principal, Depends(require(Permission.INCIDENTS_WRITE))],
    request: Request,
    db: DbSession,
) -> IncidentOut:
    """Create an incident from selected alerts, or attach them to an existing incident."""
    alerts = db.scalars(select(Alert).where(Alert.id.in_(body.alert_ids))).all()
    if len(alerts) != len(set(body.alert_ids)):
        raise not_found("one or more alerts")
    if len({a.is_synthetic for a in alerts}) > 1:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "demo and live alerts cannot be mixed in one incident",
        )
    ranks = [Severity(a.severity).rank for a in alerts]
    top = list(Severity)[max(ranks)]
    if body.incident_id:
        incident = db.get(Incident, body.incident_id)
        if incident is None:
            raise not_found("incident")
    else:
        incident = Incident(
            number=next_incident_number(db),
            title=body.title or alerts[0].title,
            description=f"Escalated by {principal.user.display_name} from {len(alerts)} alert(s).",
            severity=top.value,
            started_at=min(a.first_event_at for a in alerts),
            ended_at=max(a.last_event_at for a in alerts),
            created_by=principal.id,
            first_triaged_at=utcnow(),
            is_synthetic=alerts[0].is_synthetic,
            endpoint_ids=[],
            attack_techniques=[],
            attack_tactics=[],
        )
        db.add(incident)
        db.flush()
    for alert in alerts:
        alert.incident_id = incident.id
        if alert.status == AlertStatus.OPEN.value:
            alert.status = AlertStatus.ACKNOWLEDGED.value
            alert.triaged_at = alert.triaged_at or utcnow()
        if str(alert.endpoint_id) not in incident.endpoint_ids:
            incident.endpoint_ids = [*incident.endpoint_ids, str(alert.endpoint_id)]
        incident.attack_techniques = sorted(
            set(incident.attack_techniques) | set(alert.attack_techniques)
        )
        incident.attack_tactics = sorted(set(incident.attack_tactics) | set(alert.attack_tactics))
        linked = set(
            db.scalars(
                select(IncidentEvent.event_id).where(IncidentEvent.incident_id == incident.id)
            )
        )
        for event_id in db.scalars(
            select(AlertEvent.event_id).where(AlertEvent.alert_id == alert.id)
        ):
            if event_id not in linked:
                db.add(
                    IncidentEvent(incident_id=incident.id, event_id=event_id, added_by="analyst")
                )
                linked.add(event_id)
    if Severity(incident.severity).rank < top.rank:
        incident.severity = top.value
    db.add(
        Investigation(
            incident_id=incident.id,
            entry_type="change",
            author_id=principal.id,
            author_name=principal.user.display_name,
            body=f"{len(alerts)} alert(s) linked to the incident.",
            changes={"alerts": [str(a.id) for a in alerts]},
        )
    )
    audit.record(
        db,
        action="incident.escalate",
        resource_type="incident",
        resource_id=incident.id,
        actor_id=principal.id,
        actor_email=principal.user.email,
        ip_address=client_ip(request),
        details={"alerts": [str(a.id) for a in alerts]},
    )
    db.commit()
    return IncidentOut.model_validate(incident)
