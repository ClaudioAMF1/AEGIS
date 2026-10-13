"""Demo mode: replays synthetic scenarios through the real pipeline and resets demo data.

Every row produced here is flagged ``is_synthetic`` and tagged with the scenario id in
``events.dataset``. Live telemetry is never touched by reset.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from aegis.config import get_settings
from aegis.db import session_factory, utcnow
from aegis.demo.scenarios import Scenario, expand, load_scenarios
from aegis.events import pipeline
from aegis.models import (
    Agent,
    AgentStatus,
    Alert,
    AssistantQuery,
    Endpoint,
    Event,
    Incident,
    Report,
    ResponseAction,
    RuleMatch,
    Simulation,
    ThreatIndicator,
)
from aegis.realtime import hub
from aegis.security.crypto import hash_token, new_token

log = logging.getLogger(__name__)
_BATCH = 200
_running: dict[uuid.UUID, threading.Event] = {}


def scenarios_dir() -> Path:
    return Path(get_settings().scenarios_dir).resolve()


def available() -> dict[str, Scenario]:
    return load_scenarios(scenarios_dir())


def _demo_agent(db: Session, hostname: str) -> Agent:
    name = f"demo:{hostname}"
    agent = db.scalar(select(Agent).where(Agent.name == name, Agent.is_synthetic.is_(True)))
    if agent is None:
        agent = Agent(
            name=name,
            token_hash=hash_token(new_token("demo_")),
            token_prefix="demo",  # noqa: S106 - label, not a secret
            status=AgentStatus.ACTIVE.value,
            is_synthetic=True,
            version="demo",
        )
        db.add(agent)
        db.flush()
    return agent


DEMO_INDICATORS = [
    ("ipv4", "203.0.113.45", "SSH brute-force source (lab fixture)", "high", 80),
    ("ipv4", "198.51.100.23", "Command-and-control listener (lab fixture)", "critical", 90),
    ("domain", "updates.example-cdn.test", "Payload staging domain (lab fixture)", "high", 70),
    ("cidr", "192.0.2.0/24", "Mining pool range (lab fixture)", "medium", 60),
]


def seed_indicators(db: Session) -> int:
    created = 0
    for kind, value, description, severity, confidence in DEMO_INDICATORS:
        exists = db.scalar(
            select(ThreatIndicator).where(
                ThreatIndicator.value == value, ThreatIndicator.source == "aegis-demo"
            )
        )
        if exists is None:
            db.add(
                ThreatIndicator(
                    type=kind,
                    value=value,
                    source="aegis-demo",
                    description=description,
                    severity=severity,
                    confidence=confidence,
                    tags=["demo"],
                    is_synthetic=True,
                    license="CC0 (synthetic)",
                )
            )
            created += 1
    db.flush()
    return created


def start(
    db: Session,
    scenario_id: str,
    user_id: uuid.UUID | None,
    *,
    speed: float = 0,
    seed: int = 1337,
    end_at: datetime | None = None,
) -> Simulation:
    """Run a scenario. ``speed == 0`` ingests everything immediately; otherwise events are
    replayed in (compressed) real time in a background thread: ``speed=60`` plays one minute
    of scenario time per second."""
    scenarios = available()
    if scenario_id not in scenarios:
        raise KeyError(scenario_id)
    scenario = scenarios[scenario_id]
    seed_indicators(db)
    # Instant runs are placed so they finish "now"; realtime replays start now.
    anchor = (end_at or utcnow()) - scenario.duration if speed == 0 else utcnow()
    events = expand(scenario, anchor, seed=seed)
    simulation = Simulation(
        scenario=scenario_id,
        status="running",
        started_by=user_id,
        details={
            "speed": speed,
            "seed": seed,
            "total_events": len(events),
            "anchor": anchor.isoformat(),
        },
    )
    db.add(simulation)
    db.commit()
    if speed == 0:
        _ingest_all(db, simulation, scenario, events)
        return simulation
    stop = threading.Event()
    _running[simulation.id] = stop
    thread = threading.Thread(
        target=_replay,
        args=(simulation.id, scenario, events, speed, stop),
        daemon=True,
        name=f"demo-{scenario_id}",
    )
    thread.start()
    return simulation


def _send(
    db: Session, simulation: Simulation, scenario: Scenario, batch: list[dict[str, Any]]
) -> None:
    by_host: dict[str, list[dict[str, Any]]] = {}
    for event in batch:
        by_host.setdefault(event["host"]["hostname"], []).append(event)
    for hostname, items in by_host.items():
        agent = _demo_agent(db, hostname)
        outcome = pipeline.ingest(db, agent, items, dataset=scenario.id)
        simulation.events_sent += outcome.result.accepted
        if outcome.result.rejected:
            log.warning(
                "demo %s: %d events rejected: %s",
                scenario.id,
                len(outcome.result.rejected),
                outcome.result.rejected[0].reason,
            )
        if outcome.detection:
            simulation.alerts_created += len(outcome.detection.alerts_created)


def _ingest_all(
    db: Session, simulation: Simulation, scenario: Scenario, events: list[dict[str, Any]]
) -> None:
    try:
        for i in range(0, len(events), _BATCH):
            _send(db, simulation, scenario, events[i : i + _BATCH])
        simulation.status = "completed"
    except Exception as exc:
        log.exception("demo scenario failed")
        db.rollback()
        simulation.status = "failed"
        simulation.details = {**simulation.details, "error": type(exc).__name__}
    simulation.finished_at = utcnow()
    db.commit()
    hub.publish({"type": "simulation", "id": str(simulation.id), "status": simulation.status})


def _replay(
    simulation_id: uuid.UUID,
    scenario: Scenario,
    events: list[dict[str, Any]],
    speed: float,
    stop: threading.Event,
) -> None:
    db = session_factory()()
    try:
        simulation = db.get(Simulation, simulation_id)
        assert simulation is not None
        first = datetime.fromisoformat(events[0]["occurred_at"]) if events else utcnow()
        wall_start = time.monotonic()
        pending: list[dict[str, Any]] = []
        for event in events:
            if stop.is_set():
                simulation.status = "stopped"
                break
            offset = (datetime.fromisoformat(event["occurred_at"]) - first).total_seconds()
            due = wall_start + offset / speed
            delay = due - time.monotonic()
            if delay > 0.25 and pending:
                _send(db, simulation, scenario, pending)
                db.commit()
                pending = []
            if delay > 0:
                stop.wait(min(delay, 5.0))
            pending.append(event)
            if len(pending) >= _BATCH:
                _send(db, simulation, scenario, pending)
                db.commit()
                pending = []
        if pending and not stop.is_set():
            _send(db, simulation, scenario, pending)
        if simulation.status == "running":
            simulation.status = "completed"
        simulation.finished_at = utcnow()
        db.commit()
        hub.publish({"type": "simulation", "id": str(simulation.id), "status": simulation.status})
    except Exception:
        log.exception("demo replay failed")
        db.rollback()
        db.execute(
            update(Simulation)
            .where(Simulation.id == simulation_id)
            .values(status="failed", finished_at=utcnow())
        )
        db.commit()
    finally:
        _running.pop(simulation_id, None)
        db.close()


def stop_all() -> None:
    for flag in _running.values():
        flag.set()


def reset(db: Session) -> dict[str, int]:
    """Delete every synthetic row. Live data is untouched."""
    stop_all()
    counts: dict[str, int] = {}
    synthetic_incidents = select(Incident.id).where(Incident.is_synthetic.is_(True))
    counts["responses"] = _rowcount(
        db.execute(
            delete(ResponseAction).where(ResponseAction.incident_id.in_(synthetic_incidents))
        )
    )
    counts["reports"] = _rowcount(
        db.execute(delete(Report).where(Report.incident_id.in_(synthetic_incidents)))
    )
    counts["assistant"] = _rowcount(
        db.execute(
            delete(AssistantQuery).where(AssistantQuery.incident_id.in_(synthetic_incidents))
        )
    )
    counts["alerts"] = _rowcount(db.execute(delete(Alert).where(Alert.is_synthetic.is_(True))))
    counts["incidents"] = _rowcount(
        db.execute(delete(Incident).where(Incident.is_synthetic.is_(True)))
    )
    counts["rule_matches"] = _rowcount(
        db.execute(delete(RuleMatch).where(RuleMatch.is_synthetic.is_(True)))
    )
    counts["events"] = _rowcount(db.execute(delete(Event).where(Event.is_synthetic.is_(True))))
    counts["agents"] = _rowcount(db.execute(delete(Agent).where(Agent.is_synthetic.is_(True))))
    counts["endpoints"] = _rowcount(
        db.execute(delete(Endpoint).where(Endpoint.is_synthetic.is_(True)))
    )
    counts["indicators"] = _rowcount(
        db.execute(delete(ThreatIndicator).where(ThreatIndicator.is_synthetic.is_(True)))
    )
    db.execute(
        update(Simulation)
        .where(Simulation.status.in_(["running", "completed", "stopped", "failed"]))
        .values(status="reset")
    )
    db.commit()
    hub.publish({"type": "simulation", "status": "reset"})
    return counts


def _rowcount(result: Any) -> int:
    return int(getattr(result, "rowcount", 0) or 0)


def recent(db: Session, limit: int = 20) -> list[Simulation]:
    return list(db.scalars(select(Simulation).order_by(Simulation.started_at.desc()).limit(limit)))
