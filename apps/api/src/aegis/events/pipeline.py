"""Ingestion pipeline.

    receive (authenticated) -> validate -> identify origin -> normalise -> deduplicate
    -> enrich -> persist -> publish (broker) or detect (inline) -> realtime fan-out

The agent receives an acknowledgement only after the database commit, so a 2xx response
means the events are durable. Duplicates (same ``event_id``) are acknowledged as such and not
stored again, which makes agent retries safe.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from pydantic import ValidationError
from sqlalchemy import case, func, insert, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from aegis.config import PipelineMode, get_settings
from aegis.db import utcnow
from aegis.detection.engine import DetectionEngine, DetectionResult
from aegis.events.broker import StreamBroker
from aegis.events.contract import EventIn, IngestResult, RejectedEvent
from aegis.models import Agent, AgentStatus, Endpoint, Event
from aegis.observability import metrics
from aegis.realtime import hub
from aegis.services import intel

log = logging.getLogger(__name__)


class OriginMismatch(ValueError):
    pass


def summarize(event: EventIn) -> str:
    user = event.user.name if event.user else "?"
    if event.process and event.category == "process":
        cmd = event.process.command_line or event.process.executable or event.process.name
        return f"{user} {event.action} {cmd}"[:512]
    if event.network:
        n = event.network
        return (
            f"{event.process.name if event.process else '?'} {event.action} "
            f"{n.dst_ip}:{n.dst_port}/{n.protocol}"
        )[:512]
    if event.file:
        return f"{event.action} {event.file.path}"[:512]
    if event.auth:
        a = event.auth
        return (
            f"{event.action} {a.target_user or user} via {a.service or a.method}"
            f" from {a.source_ip or 'local'}"
        )[:512]
    return f"{event.category} {event.action}"


def observables(event: EventIn) -> dict[str, str]:
    values: dict[str, str] = {}
    if event.network:
        remote = (
            event.network.dst_ip
            if event.network.direction == "outbound"
            else (event.network.src_ip)
        )
        values["network.remote_ip"] = remote
    if event.auth and event.auth.source_ip:
        values["auth.source_ip"] = event.auth.source_ip
    if event.process and event.process.hash_sha256:
        values["process.hash_sha256"] = event.process.hash_sha256
    if event.file and event.file.hash_sha256:
        values["file.hash_sha256"] = event.file.hash_sha256
    domain = event.attributes.get("dns.query") if event.attributes else None
    if isinstance(domain, str):
        values["dns.query"] = domain.lower().rstrip(".")
    return values


@dataclass
class IngestOutcome:
    result: IngestResult
    inserted: list[Event] = field(default_factory=list)
    detection: DetectionResult | None = None


def get_or_create_endpoint(
    db: Session, hostname: str, synthetic: bool, os: str | None, ips: list[str]
) -> Endpoint:
    """Race-free upsert: concurrent first batches from one host must not collide on the
    (hostname, is_synthetic) unique constraint."""
    stmt = select(Endpoint).where(
        Endpoint.hostname == hostname, Endpoint.is_synthetic.is_(synthetic)
    )
    endpoint = db.scalar(stmt)
    if endpoint is not None:
        return endpoint
    values = {
        "id": uuid.uuid4(),
        "hostname": hostname,
        "os": os,
        "ip_addresses": ips,
        "is_synthetic": synthetic,
        "criticality": "medium",
        "tags": [],
        "first_seen_at": utcnow(),
        "isolation_state": "none",
    }
    dialect = db.get_bind().dialect.name
    if dialect in {"postgresql", "sqlite"}:
        insert_fn = pg_insert if dialect == "postgresql" else sqlite_insert
        db.execute(
            insert_fn(Endpoint)
            .values(values)
            .on_conflict_do_nothing(index_elements=["hostname", "is_synthetic"])
        )
    else:  # pragma: no cover - other dialects are not supported in production
        db.add(Endpoint(**values))
    db.flush()
    endpoint = db.scalar(stmt.execution_options(populate_existing=True))
    assert endpoint is not None
    return endpoint


def _resolve_endpoint(
    db: Session, agent: Agent, bound_id: uuid.UUID | None, event: EventIn
) -> Endpoint:
    """Endpoint for an event, enforcing that an agent only reports for the host it is bound to.

    The agent row is *not* modified here: binding is applied with an atomic UPDATE at the end of
    the transaction so concurrent batches lock rows in a consistent order."""
    if bound_id is not None:
        endpoint = db.get(Endpoint, bound_id)
        if endpoint is not None:
            if endpoint.hostname != event.host.hostname:
                raise OriginMismatch(
                    f"agent is bound to host '{endpoint.hostname}', event claims "
                    f"'{event.host.hostname}'"
                )
            return endpoint
    return get_or_create_endpoint(
        db, event.host.hostname, agent.is_synthetic, event.host.os, event.host.ip
    )


def _insert_ignore(db: Session, rows: list[dict[str, Any]]) -> set[uuid.UUID]:
    """Insert rows, silently skipping existing ``id``s. Returns the ids actually inserted."""
    if not rows:
        return set()
    dialect = db.get_bind().dialect.name
    if dialect == "postgresql":
        stmt = pg_insert(Event).values(rows).on_conflict_do_nothing(index_elements=["id"])
        return set(db.scalars(stmt.returning(Event.id)))
    if dialect == "sqlite":
        stmt_s = sqlite_insert(Event).values(rows).on_conflict_do_nothing(index_elements=["id"])
        return set(db.scalars(stmt_s.returning(Event.id)))
    existing = set(db.scalars(select(Event.id).where(Event.id.in_([r["id"] for r in rows]))))
    fresh = [r for r in rows if r["id"] not in existing]
    if fresh:
        db.execute(insert(Event), fresh)
    return {r["id"] for r in fresh}


def _parent_names(db: Session, endpoint_id: uuid.UUID, pids: set[int]) -> dict[int, str]:
    if not pids:
        return {}
    rows = db.execute(
        select(Event.process_pid, Event.process_name)
        .where(
            Event.endpoint_id == endpoint_id,
            Event.category == "process",
            Event.action == "start",
            Event.process_pid.in_(pids),
        )
        .order_by(Event.occurred_at.desc())
        .limit(500)
    ).all()
    names: dict[int, str] = {}
    for pid, name in rows:
        if pid is not None and name and pid not in names:
            names[pid] = name
    return names


def ingest(
    db: Session,
    agent: Agent,
    raw_events: list[Any],
    *,
    dataset: str | None = None,
    agent_version: str | None = None,
    buffer_depth: int | None = None,
) -> IngestOutcome:
    settings = get_settings()
    started = time.perf_counter()
    now = utcnow()
    max_future = now + timedelta(minutes=settings.ingest_max_clock_skew_minutes)
    oldest = now - timedelta(days=settings.ingest_max_event_age_days)
    if dataset is not None:  # demo replays carry historical timestamps by design
        oldest = now - timedelta(days=3650)

    rejected: list[RejectedEvent] = []
    valid: list[tuple[int, EventIn]] = []
    seen: set[uuid.UUID] = set()
    batch_duplicates = 0
    for index, raw in enumerate(raw_events):
        event_id = raw.get("event_id") if isinstance(raw, dict) else None
        try:
            event = EventIn.model_validate(raw)
        except ValidationError as exc:
            first = exc.errors()[0]
            loc = ".".join(str(p) for p in first.get("loc", ()))
            reason = f"{loc}: {first.get('msg')}" if loc else str(first.get("msg"))
            rejected.append(
                RejectedEvent(
                    index=index,
                    event_id=str(event_id)[:64] if event_id else None,
                    reason=reason[:300],
                )
            )
            metrics.EVENTS_REJECTED.labels(reason="schema").inc()
            continue
        if event.occurred_at > max_future:
            rejected.append(
                RejectedEvent(
                    index=index, event_id=str(event.event_id), reason="occurred_at is in the future"
                )
            )
            metrics.EVENTS_REJECTED.labels(reason="clock").inc()
            continue
        if event.occurred_at < oldest:
            rejected.append(
                RejectedEvent(
                    index=index,
                    event_id=str(event.event_id),
                    reason="occurred_at exceeds maximum event age",
                )
            )
            metrics.EVENTS_REJECTED.labels(reason="age").inc()
            continue
        if event.event_id in seen:
            batch_duplicates += 1
            continue
        seen.add(event.event_id)
        valid.append((index, event))

    rows: list[dict[str, Any]] = []
    endpoints: dict[str, Endpoint] = {}
    bound_id = agent.endpoint_id
    indicator_hits: dict[uuid.UUID, int] = {}
    for index, event in valid:
        try:
            endpoint = endpoints.get(event.host.hostname) or _resolve_endpoint(
                db, agent, bound_id, event
            )
            bound_id = bound_id or endpoint.id
        except OriginMismatch as exc:
            rejected.append(
                RejectedEvent(index=index, event_id=str(event.event_id), reason=str(exc))
            )
            metrics.EVENTS_REJECTED.labels(reason="origin").inc()
            continue
        endpoints[event.host.hostname] = endpoint
        payload = event.model_dump(mode="json", exclude_none=True)
        matches = intel.match_values(db, observables(event))
        for match in matches:
            indicator_hits[match.indicator.id] = indicator_hits.get(match.indicator.id, 0) + 1
        enrichment = intel.enrichment_for(matches)
        rows.append(
            {
                "id": event.event_id,
                "schema_version": event.schema_version,
                "occurred_at": event.occurred_at,
                "ingested_at": now,
                "endpoint_id": endpoint.id,
                "agent_id": agent.id,
                "seq": event.seq,
                "category": event.category.value,
                "action": event.action,
                "hostname": event.host.hostname,
                "user_name": event.user.name if event.user else None,
                "process_pid": event.process.pid if event.process else None,
                "process_ppid": event.process.ppid if event.process else None,
                "process_name": event.process.name if event.process else None,
                "src_ip": event.network.src_ip
                if event.network
                else (event.auth.source_ip if event.auth else None),
                "dst_ip": event.network.dst_ip if event.network else None,
                "dst_port": event.network.dst_port if event.network else None,
                "file_path": event.file.path if event.file else None,
                "summary": summarize(event),
                "payload": payload,
                "enrichment": enrichment,
                "is_synthetic": agent.is_synthetic,
                "dataset": dataset,
                "detection_state": "pending",
            }
        )

    # Enrichment: fill in parent process names from earlier telemetry when the agent could
    # not resolve them (short-lived parents, out-of-order delivery).
    for endpoint in endpoints.values():
        missing = {
            r["payload"]["process"]["ppid"]
            for r in rows
            if r["endpoint_id"] == endpoint.id
            and r["category"] == "process"
            and "ppid" in r["payload"].get("process", {})
            and "parent_name" not in r["payload"]["process"]
        }
        in_batch = {
            r["process_pid"]: r["process_name"]
            for r in rows
            if r["endpoint_id"] == endpoint.id and r["category"] == "process"
        }
        known = {**_parent_names(db, endpoint.id, missing - set(in_batch)), **in_batch}
        for r in rows:
            proc = r["payload"].get("process")
            if r["endpoint_id"] == endpoint.id and proc and "parent_name" not in proc:
                name = known.get(proc.get("ppid"))
                if name:
                    proc["parent_name"] = name
                    r["enrichment"] = {**r["enrichment"], "parent_resolved": True}

    inserted_ids = _insert_ignore(db, rows)
    duplicates = batch_duplicates + (len(rows) - len(inserted_ids))
    # Atomic counter updates in a fixed lock order (indicators, endpoints, agents): concurrent
    # batches neither lose increments nor deadlock.
    intel.record_hits(db, indicator_hits)
    if endpoints:
        db.execute(
            update(Endpoint)
            .where(Endpoint.id.in_(sorted(e.id for e in endpoints.values())))
            .values(last_seen_at=now)
        )
    seqs = [e.seq for _, e in valid if e.seq is not None]
    values: dict[str, Any] = {
        "events_received": Agent.events_received + len(inserted_ids),
        "events_duplicated": Agent.events_duplicated + duplicates,
        "events_rejected": Agent.events_rejected + len(rejected),
        "last_heartbeat_at": now,
    }
    if bound_id is not None:
        values["endpoint_id"] = func.coalesce(Agent.endpoint_id, bound_id)
        values["status"] = case(
            (Agent.status == AgentStatus.PENDING.value, AgentStatus.ACTIVE.value),
            else_=Agent.status,
        )
    if agent_version:
        values["version"] = agent_version
    if buffer_depth is not None:
        values["buffer_depth"] = buffer_depth
    if seqs:
        top = max(seqs)
        values["last_seq"] = case(
            (Agent.last_seq.is_(None), top), (Agent.last_seq < top, top), else_=Agent.last_seq
        )
    db.execute(update(Agent).where(Agent.id == agent.id).values(**values))
    db.commit()

    inserted = (
        list(db.scalars(select(Event).where(Event.id.in_(inserted_ids)))) if (inserted_ids) else []
    )
    metrics.EVENTS_INGESTED.labels(synthetic=str(agent.is_synthetic).lower()).inc(len(inserted))
    metrics.EVENTS_DUPLICATE.inc(duplicates)

    outcome = IngestOutcome(
        result=IngestResult(
            accepted=len(inserted),
            duplicates=duplicates,
            rejected=rejected,
            ingested_at=now,
            pipeline=settings.pipeline_mode.value,
        ),
        inserted=inserted,
    )
    if inserted:
        dispatch(db, inserted, outcome)
    metrics.INGEST_LATENCY.observe(time.perf_counter() - started)
    return outcome


def dispatch(db: Session, events: list[Event], outcome: IngestOutcome) -> None:
    settings = get_settings()
    hub.publish(
        {
            "type": "events",
            "count": len(events),
            "synthetic": any(e.is_synthetic for e in events),
            "items": [
                {
                    "id": str(e.id),
                    "occurred_at": e.occurred_at.isoformat(),
                    "category": e.category,
                    "action": e.action,
                    "hostname": e.hostname,
                    "summary": e.summary,
                    "is_synthetic": e.is_synthetic,
                }
                for e in events[-20:]
            ],
        }
    )
    if settings.pipeline_mode == PipelineMode.BROKER:
        StreamBroker().publish(e.id for e in events)
        return
    outcome.detection = run_detection(db, events, trigger="inline")


def run_detection(db: Session, events: list[Event], *, trigger: str) -> DetectionResult:
    result = DetectionEngine().process(db, events, trigger=trigger)
    db.commit()
    if result.alerts_created or result.alerts_updated:
        hub.publish(
            {
                "type": "alerts",
                "created": [str(a) for a in result.alerts_created],
                "updated": [str(a) for a in set(result.alerts_updated)],
                "incidents": [str(i) for i in result.incidents_touched],
            }
        )
    return result
