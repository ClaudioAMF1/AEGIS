"""Investigation helpers: process trees and entity graphs built from persisted telemetry."""

from __future__ import annotations

import uuid
from collections import defaultdict
from collections.abc import Sequence
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.models import Alert, AlertEvent, Endpoint, Event
from aegis.schemas import Graph, GraphEdge, GraphNode, ProcessNode

_MAX_TREE_EVENTS = 5000


def process_tree(
    db: Session,
    endpoint_id: uuid.UUID,
    *,
    since: datetime | None = None,
    until: datetime | None = None,
    event_ids: set[uuid.UUID] | None = None,
) -> list[ProcessNode]:
    stmt = select(Event).where(
        Event.endpoint_id == endpoint_id, Event.category == "process", Event.action == "start"
    )
    if since is not None:
        stmt = stmt.where(Event.occurred_at >= since)
    if until is not None:
        stmt = stmt.where(Event.occurred_at <= until)
    events = db.scalars(stmt.order_by(Event.occurred_at).limit(_MAX_TREE_EVENTS)).all()
    flagged = set(
        db.scalars(
            select(AlertEvent.event_id)
            .join(Alert, Alert.id == AlertEvent.alert_id)
            .where(Alert.endpoint_id == endpoint_id)
        )
    ) | (event_ids or set())
    return build_tree(events, flagged)


def build_tree(events: Sequence[Event], flagged: set[uuid.UUID]) -> list[ProcessNode]:
    nodes: list[ProcessNode] = []
    latest_by_pid: dict[int, ProcessNode] = {}
    roots: list[ProcessNode] = []
    for event in events:
        proc = event.payload.get("process", {})
        node = ProcessNode(
            pid=proc.get("pid", event.process_pid or 0),
            ppid=proc.get("ppid"),
            name=proc.get("name", event.process_name or "?"),
            command_line=proc.get("command_line"),
            user=(event.payload.get("user") or {}).get("name"),
            started_at=event.occurred_at,
            event_id=event.id,
            flagged=event.id in flagged,
        )
        # PIDs are reused: the parent is the most recent process with that pid started before.
        parent = latest_by_pid.get(node.ppid) if node.ppid is not None else None
        if parent is not None and parent is not node:
            parent.children.append(node)
        else:
            if node.ppid is not None and node.ppid not in latest_by_pid:
                parent_name = proc.get("parent_name")
                if parent_name:
                    synthetic_parent = ProcessNode(
                        pid=node.ppid,
                        ppid=None,
                        name=parent_name,
                        command_line=None,
                        user=None,
                        started_at=None,
                        event_id=None,
                        children=[node],
                    )
                    latest_by_pid[node.ppid] = synthetic_parent
                    roots.append(synthetic_parent)
                    nodes.append(node)
                    latest_by_pid[node.pid] = node
                    continue
            roots.append(node)
        nodes.append(node)
        latest_by_pid[node.pid] = node
    return roots


def entity_graph(
    db: Session,
    events: Sequence[Event],
    *,
    max_nodes: int = 400,
) -> Graph:
    nodes: dict[str, GraphNode] = {}
    edges: dict[str, GraphEdge] = {}
    truncated = False
    event_ids = [e.id for e in events]
    alert_rows = (
        db.execute(
            select(AlertEvent.event_id, Alert)
            .join(Alert, Alert.id == AlertEvent.alert_id)
            .where(AlertEvent.event_id.in_(event_ids))
        ).all()
        if event_ids
        else []
    )
    alerts_by_event: dict[uuid.UUID, list[Alert]] = defaultdict(list)
    for event_id, alert in alert_rows:
        alerts_by_event[event_id].append(alert)
    endpoints = (
        {
            e.id: e
            for e in db.scalars(
                select(Endpoint).where(Endpoint.id.in_({ev.endpoint_id for ev in events}))
            )
        }
        if events
        else {}
    )

    def node(node_id: str, kind: str, label: str, **data: object) -> str | None:
        nonlocal truncated
        if node_id in nodes:
            nodes[node_id].weight += 1
            return node_id
        if len(nodes) >= max_nodes:
            truncated = True
            return None
        nodes[node_id] = GraphNode(id=node_id, kind=kind, label=label, data=dict(data))
        return node_id

    def edge(source: str | None, target: str | None, kind: str, when: datetime) -> None:
        if source is None or target is None or source == target:
            return
        key = f"{source}>{target}:{kind}"
        current = edges.get(key)
        if current is None:
            edges[key] = GraphEdge(
                id=key, source=source, target=target, kind=kind, first_seen=when, last_seen=when
            )
        else:
            current.count += 1
            current.first_seen = min(current.first_seen or when, when)
            current.last_seen = max(current.last_seen or when, when)

    for event in events:
        endpoint = endpoints.get(event.endpoint_id)
        host_id = node(
            f"host:{event.endpoint_id}",
            "host",
            event.hostname,
            endpoint_id=str(event.endpoint_id),
            criticality=endpoint.criticality if endpoint else None,
        )
        payload = event.payload
        proc = payload.get("process") or {}
        user = (payload.get("user") or {}).get("name")
        proc_id = None
        if proc.get("name"):
            proc_id = node(
                f"proc:{event.endpoint_id}:{proc['name']}",
                "process",
                proc["name"],
                host=event.hostname,
            )
            if proc_id and event.category == "process":
                pids = nodes[proc_id].data.setdefault("pids", [])
                if isinstance(pids, list) and len(pids) < 20 and proc.get("pid") not in pids:
                    pids.append(proc.get("pid"))
            edge(host_id, proc_id, "runs", event.occurred_at)
            parent = proc.get("parent_name")
            if parent and event.category == "process":
                parent_id = node(
                    f"proc:{event.endpoint_id}:{parent}", "process", parent, host=event.hostname
                )
                edge(parent_id, proc_id, "spawned", event.occurred_at)
        if user:
            user_id = node(f"user:{user}", "user", user)
            if proc_id and event.category == "process":
                edge(user_id, proc_id, "executes", event.occurred_at)
            elif event.category == "authentication":
                edge(user_id, host_id, "logs_into", event.occurred_at)
        net = payload.get("network")
        if net:
            remote = net["dst_ip"] if net.get("direction") == "outbound" else net["src_ip"]
            ip_id = node(
                f"ip:{remote}", "ip", remote, intel=bool(event.enrichment.get("intel.matched"))
            )
            edge(
                proc_id or host_id,
                ip_id,
                f"{net.get('protocol')}/{net.get('dst_port')}",
                event.occurred_at,
            )
        auth = payload.get("auth")
        if auth and auth.get("source_ip"):
            ip_id = node(
                f"ip:{auth['source_ip']}",
                "ip",
                auth["source_ip"],
                intel=bool(event.enrichment.get("intel.matched")),
            )
            edge(ip_id, host_id, f"auth_{auth.get('outcome')}", event.occurred_at)
        file = payload.get("file")
        if file and alerts_by_event.get(event.id):
            file_id = node(f"file:{event.endpoint_id}:{file['path']}", "file", file["path"])
            edge(proc_id or host_id, file_id, event.action, event.occurred_at)
        for alert in alerts_by_event.get(event.id, []):
            alert_id = node(
                f"alert:{alert.id}",
                "alert",
                alert.title,
                alert_id=str(alert.id),
                rule_id=alert.rule_id,
            )
            if alert_id:
                nodes[alert_id].severity = alert.severity
            edge(alert_id, proc_id or host_id, "flags", event.occurred_at)
            if host_id and host_id in nodes:
                current = nodes[host_id].severity
                ranks = ["informational", "low", "medium", "high", "critical"]
                if current is None or ranks.index(alert.severity) > ranks.index(current):
                    nodes[host_id].severity = alert.severity
    return Graph(nodes=list(nodes.values()), edges=list(edges.values()), truncated=truncated)
