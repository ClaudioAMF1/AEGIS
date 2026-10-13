"""Monitored endpoints and agent enrolment."""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from aegis.db import utcnow
from aegis.models import Agent, AgentStatus, Alert, AlertStatus, Endpoint, Event
from aegis.routers.common import not_found, scope_clause
from aegis.schemas import AgentOut, EndpointOut, EndpointSummary, ProcessNode, Scope
from aegis.security.crypto import hash_token, new_token
from aegis.security.deps import DbSession, Principal, client_ip, require
from aegis.security.rbac import Permission
from aegis.services import audit
from aegis.services.investigation import process_tree

router = APIRouter(tags=["endpoints"])
Reader = Annotated[Principal, Depends(require(Permission.TELEMETRY_READ))]
AgentAdmin = Annotated[Principal, Depends(require(Permission.AGENTS_MANAGE))]

ONLINE_WINDOW = timedelta(minutes=2)
STALE_WINDOW = timedelta(minutes=30)


def _status(endpoint: Endpoint) -> str:
    if endpoint.last_seen_at is None:
        return "never"
    age = utcnow() - endpoint.last_seen_at
    if age <= ONLINE_WINDOW:
        return "online"
    return "stale" if age <= STALE_WINDOW else "offline"


@router.get("/endpoints", response_model=list[EndpointSummary])
def list_endpoints(_: Reader, db: DbSession, scope: Scope = Scope.LIVE) -> list[EndpointSummary]:
    since = utcnow() - timedelta(hours=24)
    endpoints = db.scalars(
        select(Endpoint)
        .where(scope_clause(Endpoint.is_synthetic, scope))
        .order_by(Endpoint.hostname)
    ).all()
    events = dict(
        db.execute(
            select(Event.endpoint_id, func.count())
            .where(Event.ingested_at >= since)
            .group_by(Event.endpoint_id)
        ).all()
    )
    alerts = dict(
        db.execute(
            select(Alert.endpoint_id, func.count())
            .where(Alert.status != AlertStatus.CLOSED.value)
            .group_by(Alert.endpoint_id)
        ).all()
    )
    agents = dict(
        db.execute(select(Agent.endpoint_id, func.count()).group_by(Agent.endpoint_id)).all()
    )
    return [
        EndpointSummary(
            **EndpointOut.model_validate(e).model_dump(),
            status=_status(e),
            agent_count=agents.get(e.id, 0),
            events_24h=events.get(e.id, 0),
            open_alerts=alerts.get(e.id, 0),
        )
        for e in endpoints
    ]


class EndpointDetail(EndpointSummary):
    agents: list[AgentOut]
    activity: list[dict[str, Any]]


@router.get("/endpoints/{endpoint_id}", response_model=EndpointDetail)
def get_endpoint(endpoint_id: uuid.UUID, _: Reader, db: DbSession) -> EndpointDetail:
    endpoint = db.get(Endpoint, endpoint_id)
    if endpoint is None:
        raise not_found("endpoint")
    since = utcnow() - timedelta(hours=24)
    agents = db.scalars(select(Agent).where(Agent.endpoint_id == endpoint_id)).all()
    by_category = db.execute(
        select(Event.category, func.count())
        .where(Event.endpoint_id == endpoint_id)
        .group_by(Event.category)
    ).all()
    events_24h = (
        db.scalar(
            select(func.count())
            .select_from(Event)
            .where(Event.endpoint_id == endpoint_id, Event.ingested_at >= since)
        )
        or 0
    )
    open_alerts = (
        db.scalar(
            select(func.count())
            .select_from(Alert)
            .where(Alert.endpoint_id == endpoint_id, Alert.status != AlertStatus.CLOSED.value)
        )
        or 0
    )
    return EndpointDetail(
        **EndpointOut.model_validate(endpoint).model_dump(),
        status=_status(endpoint),
        agent_count=len(agents),
        events_24h=events_24h,
        open_alerts=open_alerts,
        agents=[AgentOut.model_validate(a) for a in agents],
        activity=[{"category": c, "count": n} for c, n in by_category],
    )


@router.get("/endpoints/{endpoint_id}/process-tree", response_model=list[ProcessNode])
def endpoint_process_tree(
    endpoint_id: uuid.UUID,
    _: Reader,
    db: DbSession,
    hours: Annotated[int, Query(ge=1, le=168)] = 24,
) -> list[ProcessNode]:
    if db.get(Endpoint, endpoint_id) is None:
        raise not_found("endpoint")
    return process_tree(db, endpoint_id, since=utcnow() - timedelta(hours=hours))


class EndpointPatch(BaseModel):
    criticality: Annotated[str, Field(pattern="^(low|medium|high|critical)$")] | None = None
    tags: list[Annotated[str, Field(max_length=32)]] | None = Field(default=None, max_length=16)


@router.patch("/endpoints/{endpoint_id}", response_model=EndpointOut)
def update_endpoint(
    endpoint_id: uuid.UUID,
    body: EndpointPatch,
    principal: AgentAdmin,
    request: Request,
    db: DbSession,
) -> EndpointOut:
    endpoint = db.get(Endpoint, endpoint_id)
    if endpoint is None:
        raise not_found("endpoint")
    changes = body.model_dump(exclude_none=True)
    for key, value in changes.items():
        setattr(endpoint, key, value)
    audit.record(
        db,
        action="endpoint.update",
        resource_type="endpoint",
        resource_id=endpoint.id,
        actor_id=principal.id,
        actor_email=principal.user.email,
        ip_address=client_ip(request),
        details=changes,
    )
    db.commit()
    return EndpointOut.model_validate(endpoint)


# ---------------------------------------------------------------------------
# Agents
# ---------------------------------------------------------------------------


@router.get("/agents", response_model=list[AgentOut])
def list_agents(_: Reader, db: DbSession, scope: Scope = Scope.LIVE) -> list[AgentOut]:
    rows = db.scalars(
        select(Agent)
        .where(scope_clause(Agent.is_synthetic, scope))
        .order_by(Agent.created_at.desc())
    ).all()
    return [AgentOut.model_validate(a) for a in rows]


class AgentCreate(BaseModel):
    name: Annotated[str, Field(min_length=2, max_length=120)]
    config: dict[str, Any] = Field(default_factory=dict)


class AgentEnrolled(BaseModel):
    agent: AgentOut
    token: str
    notice: str = "Store this token now: it is shown only once and kept only as a hash."


@router.post("/agents", response_model=AgentEnrolled, status_code=status.HTTP_201_CREATED)
def create_agent(
    body: AgentCreate, principal: AgentAdmin, request: Request, db: DbSession
) -> AgentEnrolled:
    token = new_token("aga_")
    agent = Agent(
        name=body.name,
        token_hash=hash_token(token),
        token_prefix=token[:10],
        config=body.config,
        status=AgentStatus.PENDING.value,
    )
    db.add(agent)
    db.flush()
    audit.record(
        db,
        action="agent.enroll",
        resource_type="agent",
        resource_id=agent.id,
        actor_id=principal.id,
        actor_email=principal.user.email,
        ip_address=client_ip(request),
        details={"name": body.name},
    )
    db.commit()
    return AgentEnrolled(agent=AgentOut.model_validate(agent), token=token)


@router.post("/agents/{agent_id}/revoke", response_model=AgentOut)
def revoke_agent(
    agent_id: uuid.UUID, principal: AgentAdmin, request: Request, db: DbSession
) -> AgentOut:
    agent = db.get(Agent, agent_id)
    if agent is None:
        raise not_found("agent")
    agent.status = AgentStatus.REVOKED.value
    audit.record(
        db,
        action="agent.revoke",
        resource_type="agent",
        resource_id=agent.id,
        actor_id=principal.id,
        actor_email=principal.user.email,
        ip_address=client_ip(request),
    )
    db.commit()
    return AgentOut.model_validate(agent)
