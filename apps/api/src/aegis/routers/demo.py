"""Demo & simulation endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from aegis.demo import runner
from aegis.security.deps import DbSession, Principal, client_ip, require
from aegis.security.rbac import Permission
from aegis.services import audit

router = APIRouter(prefix="/demo", tags=["demo"])
Reader = Annotated[Principal, Depends(require(Permission.TELEMETRY_READ))]
Runner = Annotated[Principal, Depends(require(Permission.DEMO_RUN))]
Admin = Annotated[Principal, Depends(require(Permission.SETTINGS_MANAGE))]


class SimulationOut(BaseModel):
    id: str
    scenario: str
    status: str
    started_at: datetime
    finished_at: datetime | None
    events_sent: int
    alerts_created: int
    details: dict[str, Any]


@router.get("/scenarios")
def scenarios(_: Reader) -> list[dict[str, Any]]:
    return [s.summary() for s in runner.available().values()]


@router.get("/simulations", response_model=list[SimulationOut])
def simulations(_: Reader, db: DbSession) -> list[SimulationOut]:
    return [
        SimulationOut(
            id=str(s.id),
            scenario=s.scenario,
            status=s.status,
            started_at=s.started_at,
            finished_at=s.finished_at,
            events_sent=s.events_sent,
            alerts_created=s.alerts_created,
            details=s.details,
        )
        for s in runner.recent(db)
    ]


class RunIn(BaseModel):
    scenario: Annotated[str, Field(max_length=64)]
    speed: Annotated[float, Field(ge=0, le=600)] = 0
    seed: Annotated[int, Field(ge=0, le=2**31)] = 1337


@router.post("/run", response_model=SimulationOut, status_code=status.HTTP_202_ACCEPTED)
def run(body: RunIn, principal: Runner, request: Request, db: DbSession) -> SimulationOut:
    try:
        simulation = runner.start(db, body.scenario, principal.id, speed=body.speed, seed=body.seed)
    except KeyError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scenario not found") from exc
    audit.record(
        db,
        action="demo.run",
        resource_type="simulation",
        resource_id=simulation.id,
        actor_id=principal.id,
        actor_email=principal.user.email,
        ip_address=client_ip(request),
        details=body.model_dump(),
    )
    db.commit()
    return SimulationOut(
        id=str(simulation.id),
        scenario=simulation.scenario,
        status=simulation.status,
        started_at=simulation.started_at,
        finished_at=simulation.finished_at,
        events_sent=simulation.events_sent,
        alerts_created=simulation.alerts_created,
        details=simulation.details,
    )


@router.post("/reset")
def reset(principal: Runner, request: Request, db: DbSession) -> dict[str, int]:
    counts = runner.reset(db)
    audit.record(
        db,
        action="demo.reset",
        resource_type="simulation",
        actor_id=principal.id,
        actor_email=principal.user.email,
        ip_address=client_ip(request),
        details=counts,
    )
    db.commit()
    return counts
