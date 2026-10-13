"""Incident investigation: lifecycle, journal, evidence, timeline, process tree and graph."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import AwareDatetime, BaseModel, Field
from sqlalchemy import func, select

from aegis.db import utcnow
from aegis.models import (
    Alert,
    Endpoint,
    Event,
    Evidence,
    Incident,
    IncidentEvent,
    IncidentStatus,
    Investigation,
    ResponseAction,
    Severity,
    User,
)
from aegis.routers.alerts import hostnames_for, to_out
from aegis.routers.common import not_found, scope_clause
from aegis.schemas import (
    EndpointOut,
    EventOut,
    EvidenceOut,
    Graph,
    IncidentDetail,
    IncidentOut,
    JournalEntry,
    Page,
    ProcessNode,
    Scope,
)
from aegis.security.deps import DbSession, Principal, client_ip, require
from aegis.security.rbac import Permission
from aegis.services import audit
from aegis.services.alerting import next_incident_number
from aegis.services.investigation import build_tree, entity_graph

router = APIRouter(prefix="/incidents", tags=["incidents"])
Reader = Annotated[Principal, Depends(require(Permission.TELEMETRY_READ))]
Writer = Annotated[Principal, Depends(require(Permission.INCIDENTS_WRITE))]

# Allowed status transitions. Re-opening a closed incident is explicit and journaled.
TRANSITIONS: dict[str, set[str]] = {
    "new": {"investigating", "contained", "resolved", "false_positive"},
    "investigating": {"contained", "resolved", "false_positive"},
    "contained": {"investigating", "resolved"},
    "resolved": {"investigating"},
    "false_positive": {"investigating"},
}


def _counts(
    db: DbSession, ids: list[uuid.UUID]
) -> tuple[dict[uuid.UUID, int], dict[uuid.UUID, int]]:
    if not ids:
        return {}, {}
    alerts = dict(
        db.execute(
            select(Alert.incident_id, func.count())
            .where(Alert.incident_id.in_(ids))
            .group_by(Alert.incident_id)
        ).all()
    )
    events = dict(
        db.execute(
            select(IncidentEvent.incident_id, func.count())
            .where(IncidentEvent.incident_id.in_(ids))
            .group_by(IncidentEvent.incident_id)
        ).all()
    )
    return alerts, events  # type: ignore[return-value]


def _out(
    incident: Incident, alerts: dict[uuid.UUID, int], events: dict[uuid.UUID, int]
) -> IncidentOut:
    return IncidentOut.model_validate(incident).model_copy(
        update={
            "alert_count": alerts.get(incident.id, 0),
            "event_count": events.get(incident.id, 0),
            "assignee_name": incident.assignee.display_name if incident.assignee else None,
        }
    )


def _get(db: DbSession, incident_id: uuid.UUID) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise not_found("incident")
    return incident


@router.get("", response_model=Page[IncidentOut])
def list_incidents(
    _: Reader,
    db: DbSession,
    scope: Scope = Scope.LIVE,
    status_: Annotated[list[IncidentStatus] | None, Query(alias="status")] = None,
    severity: Severity | None = None,
    assignee_id: uuid.UUID | None = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[IncidentOut]:
    filters = [scope_clause(Incident.is_synthetic, scope)]
    if status_:
        filters.append(Incident.status.in_([s.value for s in status_]))
    if severity:
        filters.append(Incident.severity == severity.value)
    if assignee_id:
        filters.append(Incident.assignee_id == assignee_id)
    if q:
        escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        filters.append(Incident.title.ilike(f"%{escaped}%", escape="\\"))
    total = db.scalar(select(func.count()).select_from(Incident).where(*filters))
    rows = db.scalars(
        select(Incident)
        .where(*filters)
        .order_by(Incident.updated_at.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    alerts, events = _counts(db, [r.id for r in rows])
    return Page(items=[_out(r, alerts, events) for r in rows], total=total)


class IncidentCreate(BaseModel):
    title: Annotated[str, Field(min_length=3, max_length=255)]
    description: Annotated[str, Field(max_length=10_000)] = ""
    severity: Severity = Severity.MEDIUM
    started_at: AwareDatetime | None = None
    endpoint_ids: list[uuid.UUID] = Field(default_factory=list, max_length=50)
    event_ids: list[uuid.UUID] = Field(default_factory=list, max_length=500)
    is_synthetic: bool = False


@router.post("", response_model=IncidentOut, status_code=status.HTTP_201_CREATED)
def create_incident(
    body: IncidentCreate, principal: Writer, request: Request, db: DbSession
) -> IncidentOut:
    events = (
        db.scalars(select(Event).where(Event.id.in_(body.event_ids))).all()
        if (body.event_ids)
        else []
    )
    endpoint_ids = {str(e) for e in body.endpoint_ids} | {str(e.endpoint_id) for e in events}
    incident = Incident(
        number=next_incident_number(db),
        title=body.title,
        description=body.description,
        severity=body.severity.value,
        started_at=body.started_at or (min(e.occurred_at for e in events) if events else utcnow()),
        created_by=principal.id,
        first_triaged_at=utcnow(),
        endpoint_ids=sorted(endpoint_ids),
        attack_techniques=[],
        attack_tactics=[],
        is_synthetic=body.is_synthetic or any(e.is_synthetic for e in events),
    )
    db.add(incident)
    db.flush()
    for event in events:
        db.add(IncidentEvent(incident_id=incident.id, event_id=event.id, added_by="analyst"))
    db.add(
        Investigation(
            incident_id=incident.id,
            entry_type="system",
            author_id=principal.id,
            author_name=principal.user.display_name,
            body="Incident opened manually.",
        )
    )
    audit.record(
        db,
        action="incident.create",
        resource_type="incident",
        resource_id=incident.id,
        actor_id=principal.id,
        actor_email=principal.user.email,
        ip_address=client_ip(request),
    )
    db.commit()
    return _out(incident, {}, {incident.id: len(events)})


@router.get("/{incident_id}", response_model=IncidentDetail)
def get_incident(incident_id: uuid.UUID, _: Reader, db: DbSession) -> IncidentDetail:
    incident = _get(db, incident_id)
    alerts = db.scalars(
        select(Alert).where(Alert.incident_id == incident_id).order_by(Alert.first_event_at)
    ).all()
    names = hostnames_for(db, {a.endpoint_id for a in alerts})
    endpoint_uuids = [uuid.UUID(e) for e in incident.endpoint_ids]
    endpoints = db.scalars(select(Endpoint).where(Endpoint.id.in_(endpoint_uuids))).all()
    evidence = db.scalars(
        select(Evidence).where(Evidence.incident_id == incident_id).order_by(Evidence.created_at)
    ).all()
    journal = db.scalars(
        select(Investigation)
        .where(Investigation.incident_id == incident_id)
        .order_by(Investigation.created_at)
    ).all()
    responses = db.scalars(
        select(ResponseAction)
        .where(ResponseAction.incident_id == incident_id)
        .order_by(ResponseAction.requested_at)
    ).all()
    alert_counts, event_counts = _counts(db, [incident.id])
    base = _out(incident, alert_counts, event_counts)
    return IncidentDetail(
        **base.model_dump(),
        alerts=[to_out(a, names) for a in alerts],
        endpoints=[EndpointOut.model_validate(e) for e in endpoints],
        evidence=[EvidenceOut.model_validate(e) for e in evidence],
        journal=[JournalEntry.model_validate(j) for j in journal],
        responses=[
            {
                "id": str(r.id),
                "action_type": r.action_type,
                "status": r.status,
                "target_type": r.target_type,
                "target_id": r.target_id,
                "requested_at": r.requested_at,
                "result": r.result,
            }
            for r in responses
        ],
    )


class IncidentPatch(BaseModel):
    title: Annotated[str, Field(min_length=3, max_length=255)] | None = None
    description: Annotated[str, Field(max_length=10_000)] | None = None
    status: IncidentStatus | None = None
    severity: Severity | None = None
    assignee_id: uuid.UUID | None = None
    unassign: bool = False
    note: Annotated[str, Field(max_length=4000)] | None = None


@router.patch("/{incident_id}", response_model=IncidentOut)
def update_incident(
    incident_id: uuid.UUID, body: IncidentPatch, principal: Writer, request: Request, db: DbSession
) -> IncidentOut:
    incident = _get(db, incident_id)
    changes: dict[str, Any] = {}
    if body.status and body.status.value != incident.status:
        if body.status.value not in TRANSITIONS[incident.status]:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"cannot move from {incident.status} to {body.status.value}",
            )
        changes["status"] = [incident.status, body.status.value]
        incident.status = body.status.value
        if incident.first_triaged_at is None:
            incident.first_triaged_at = utcnow()
        if body.status in (IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE):
            incident.resolved_at = utcnow()
        else:
            incident.resolved_at = None
    for field in ("title", "description"):
        value = getattr(body, field)
        if value is not None and value != getattr(incident, field):
            changes[field] = [getattr(incident, field)[:200], value[:200]]
            setattr(incident, field, value)
    if body.severity and body.severity.value != incident.severity:
        changes["severity"] = [incident.severity, body.severity.value]
        incident.severity = body.severity.value
    if body.assignee_id or body.unassign:
        if body.assignee_id:
            assignee = db.get(User, body.assignee_id)
            if assignee is None or not assignee.is_active or assignee.role == "viewer":
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_CONTENT,
                    "assignee must be an active analyst or administrator",
                )
        changes["assignee_id"] = [
            str(incident.assignee_id) if incident.assignee_id else None,
            str(body.assignee_id) if body.assignee_id else None,
        ]
        incident.assignee_id = body.assignee_id
        if incident.first_triaged_at is None:
            incident.first_triaged_at = utcnow()
    if not changes and not body.note:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "no changes")
    incident.updated_at = utcnow()
    db.add(
        Investigation(
            incident_id=incident.id,
            entry_type="change" if changes else "comment",
            author_id=principal.id,
            author_name=principal.user.display_name,
            body=body.note or "",
            changes=changes,
        )
    )
    audit.record(
        db,
        action="incident.update",
        resource_type="incident",
        resource_id=incident.id,
        actor_id=principal.id,
        actor_email=principal.user.email,
        ip_address=client_ip(request),
        details={"changes": changes},
    )
    db.commit()
    db.refresh(incident)
    alerts, events = _counts(db, [incident.id])
    return _out(incident, alerts, events)


class CommentIn(BaseModel):
    body: Annotated[str, Field(min_length=1, max_length=8000)]


@router.post(
    "/{incident_id}/comments", response_model=JournalEntry, status_code=status.HTTP_201_CREATED
)
def add_comment(
    incident_id: uuid.UUID, body: CommentIn, principal: Writer, db: DbSession
) -> JournalEntry:
    incident = _get(db, incident_id)
    entry = Investigation(
        incident_id=incident.id,
        entry_type="comment",
        author_id=principal.id,
        author_name=principal.user.display_name,
        body=body.body,
    )
    db.add(entry)
    if incident.first_triaged_at is None:
        incident.first_triaged_at = utcnow()
    incident.updated_at = utcnow()
    db.commit()
    return JournalEntry.model_validate(entry)


class EvidenceIn(BaseModel):
    kind: Annotated[str, Field(pattern="^(event|alert|indicator|note)$")]
    reference: Annotated[str, Field(max_length=64)] | None = None
    label: Annotated[str, Field(min_length=1, max_length=255)]
    data: dict[str, Any] = Field(default_factory=dict)


@router.post(
    "/{incident_id}/evidence", response_model=EvidenceOut, status_code=status.HTTP_201_CREATED
)
def add_evidence(
    incident_id: uuid.UUID, body: EvidenceIn, principal: Writer, request: Request, db: DbSession
) -> EvidenceOut:
    incident = _get(db, incident_id)
    if body.kind == "event" and body.reference:
        try:
            event = db.get(Event, uuid.UUID(body.reference))
        except ValueError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid event id") from exc
        if event is None:
            raise not_found("event")
        if db.get(IncidentEvent, (incident.id, event.id)) is None:
            db.add(IncidentEvent(incident_id=incident.id, event_id=event.id, added_by="analyst"))
    evidence = Evidence(
        incident_id=incident.id,
        kind=body.kind,
        reference=body.reference,
        label=body.label,
        data=body.data,
        created_by=principal.id,
    )
    db.add(evidence)
    db.add(
        Investigation(
            incident_id=incident.id,
            entry_type="change",
            author_id=principal.id,
            author_name=principal.user.display_name,
            body=f"Evidence added: {body.label}",
            changes={"evidence_kind": body.kind, "reference": body.reference},
        )
    )
    audit.record(
        db,
        action="incident.evidence_add",
        resource_type="incident",
        resource_id=incident.id,
        actor_id=principal.id,
        actor_email=principal.user.email,
        ip_address=client_ip(request),
        details={"kind": body.kind, "reference": body.reference},
    )
    incident.updated_at = utcnow()
    db.commit()
    return EvidenceOut.model_validate(evidence)


@router.get("/{incident_id}/events", response_model=list[EventOut])
def incident_events(
    incident_id: uuid.UUID,
    _: Reader,
    db: DbSession,
    context_minutes: Annotated[int, Query(ge=0, le=240)] = 0,
    limit: Annotated[int, Query(ge=1, le=5000)] = 1000,
) -> list[EventOut]:
    """Timeline: linked events, optionally widened with surrounding telemetry from the same
    endpoints (context) so analysts can see what happened before and after detections."""
    incident = _get(db, incident_id)
    linked = db.scalars(
        select(Event)
        .join(IncidentEvent, IncidentEvent.event_id == Event.id)
        .where(IncidentEvent.incident_id == incident_id)
        .order_by(Event.occurred_at)
        .limit(limit)
    ).all()
    events = {e.id: e for e in linked}
    if context_minutes and linked:
        start = min(e.occurred_at for e in linked) - timedelta(minutes=context_minutes)
        end = max(e.occurred_at for e in linked) + timedelta(minutes=context_minutes)
        endpoint_ids = [uuid.UUID(e) for e in incident.endpoint_ids]
        for e in db.scalars(
            select(Event)
            .where(Event.endpoint_id.in_(endpoint_ids), Event.occurred_at.between(start, end))
            .order_by(Event.occurred_at)
            .limit(limit)
        ):
            events.setdefault(e.id, e)
    return [
        EventOut.model_validate(e) for e in sorted(events.values(), key=lambda e: e.occurred_at)
    ]


@router.get("/{incident_id}/process-tree", response_model=dict[str, list[ProcessNode]])
def incident_process_tree(
    incident_id: uuid.UUID, _: Reader, db: DbSession
) -> dict[str, list[ProcessNode]]:
    incident = _get(db, incident_id)
    linked_ids = set(
        db.scalars(select(IncidentEvent.event_id).where(IncidentEvent.incident_id == incident_id))
    )
    start = incident.started_at - timedelta(hours=1)
    end = (incident.ended_at or utcnow()) + timedelta(minutes=30)
    trees: dict[str, list[ProcessNode]] = {}
    for endpoint_id in incident.endpoint_ids:
        events = db.scalars(
            select(Event)
            .where(
                Event.endpoint_id == uuid.UUID(endpoint_id),
                Event.category == "process",
                Event.action == "start",
                Event.occurred_at.between(start, end),
            )
            .order_by(Event.occurred_at)
            .limit(3000)
        ).all()
        hostname = events[0].hostname if events else endpoint_id
        trees[hostname] = build_tree(events, linked_ids)
    return trees


@router.get("/{incident_id}/graph", response_model=Graph)
def incident_graph(incident_id: uuid.UUID, _: Reader, db: DbSession) -> Graph:
    _get(db, incident_id)
    events = db.scalars(
        select(Event)
        .join(IncidentEvent, IncidentEvent.event_id == Event.id)
        .where(IncidentEvent.incident_id == incident_id)
        .order_by(Event.occurred_at)
        .limit(2000)
    ).all()
    return entity_graph(db, events)


@router.get("/{incident_id}/export")
def export_incident(incident_id: uuid.UUID, _: Reader, db: DbSession) -> dict[str, Any]:
    detail = get_incident(incident_id, _, db)
    events = incident_events(incident_id, _, db, 0, 5000)
    return {
        "exported_at": datetime.now().astimezone().isoformat(),
        "incident": detail.model_dump(mode="json"),
        "events": [e.model_dump(mode="json") for e in events],
        "scope_note": "Synthetic demo data" if detail.is_synthetic else "Live telemetry",
    }
