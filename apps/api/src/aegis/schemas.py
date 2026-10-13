"""Response/request models shared by the read-side routers."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict


class Scope(StrEnum):
    """Which data a query sees. Live and Demo data are never mixed unless asked for."""

    LIVE = "live"
    DEMO = "demo"
    ALL = "all"


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Page[T](BaseModel):
    items: list[T]
    total: int | None = None
    next_cursor: str | None = None


class EndpointOut(ORM):
    id: uuid.UUID
    hostname: str
    os: str | None
    ip_addresses: list[str]
    criticality: str
    tags: list[str]
    is_synthetic: bool
    first_seen_at: datetime
    last_seen_at: datetime | None
    isolation_state: str


class EndpointSummary(EndpointOut):
    status: str  # online | stale | offline | never
    agent_count: int
    events_24h: int
    open_alerts: int


class AgentOut(ORM):
    id: uuid.UUID
    name: str
    endpoint_id: uuid.UUID | None
    token_prefix: str
    status: str
    version: str | None
    is_synthetic: bool
    config: dict[str, Any]
    created_at: datetime
    last_heartbeat_at: datetime | None
    last_seq: int | None
    events_received: int
    events_duplicated: int
    events_rejected: int
    buffer_depth: int | None


class EventOut(ORM):
    id: uuid.UUID
    occurred_at: datetime
    ingested_at: datetime
    endpoint_id: uuid.UUID
    hostname: str
    category: str
    action: str
    user_name: str | None
    process_pid: int | None
    process_ppid: int | None
    process_name: str | None
    src_ip: str | None
    dst_ip: str | None
    dst_port: int | None
    file_path: str | None
    summary: str
    is_synthetic: bool
    dataset: str | None
    detection_state: str


class EventDetail(EventOut):
    schema_version: str
    seq: int | None
    agent_id: uuid.UUID | None
    payload: dict[str, Any]
    enrichment: dict[str, Any]
    alert_ids: list[uuid.UUID] = []
    rule_ids: list[str] = []


class RuleOut(ORM):
    id: uuid.UUID
    rule_id: str
    version: int
    title: str
    description: str
    kind: str
    source: str
    severity: str
    enabled: bool
    generates_alerts: bool
    attack_techniques: list[str]
    attack_tactics: list[str]
    false_positives: list[str]
    references: list[str]
    created_at: datetime
    updated_at: datetime
    match_count: int
    last_matched_at: datetime | None


class RuleDetail(RuleOut):
    content: str
    content_sha256: str
    versions: list[dict[str, Any]] = []


class AlertOut(ORM):
    id: uuid.UUID
    rule_id: str
    rule_version: int
    title: str
    severity: str
    status: str
    disposition: str
    endpoint_id: uuid.UUID
    hostname: str | None = None
    hit_count: int
    first_event_at: datetime
    last_event_at: datetime
    created_at: datetime
    updated_at: datetime
    triaged_at: datetime | None
    attack_techniques: list[str]
    attack_tactics: list[str]
    context: dict[str, Any]
    incident_id: uuid.UUID | None
    is_synthetic: bool


class AlertDetail(AlertOut):
    events: list[EventOut] = []
    rule: RuleOut | None = None


class IncidentOut(ORM):
    id: uuid.UUID
    number: int
    title: str
    description: str
    status: str
    severity: str
    started_at: datetime
    ended_at: datetime | None
    detected_at: datetime
    first_triaged_at: datetime | None
    resolved_at: datetime | None
    assignee_id: uuid.UUID | None
    assignee_name: str | None = None
    attack_techniques: list[str]
    attack_tactics: list[str]
    endpoint_ids: list[str]
    is_synthetic: bool
    created_at: datetime
    updated_at: datetime
    alert_count: int = 0
    event_count: int = 0


class JournalEntry(ORM):
    id: uuid.UUID
    entry_type: str
    author_id: uuid.UUID | None
    author_name: str
    body: str
    changes: dict[str, Any]
    created_at: datetime


class EvidenceOut(ORM):
    id: uuid.UUID
    kind: str
    reference: str | None
    label: str
    data: dict[str, Any]
    created_by: uuid.UUID | None
    created_at: datetime


class IncidentDetail(IncidentOut):
    alerts: list[AlertOut] = []
    endpoints: list[EndpointOut] = []
    evidence: list[EvidenceOut] = []
    journal: list[JournalEntry] = []
    responses: list[dict[str, Any]] = []


class GraphNode(BaseModel):
    id: str
    kind: str  # host | process | user | ip | file | alert
    label: str
    data: dict[str, Any] = {}
    severity: str | None = None
    weight: int = 1


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    kind: str
    count: int = 1
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class Graph(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    truncated: bool = False
    window: dict[str, datetime | None] = {}


class ProcessNode(BaseModel):
    pid: int
    ppid: int | None
    name: str
    command_line: str | None
    user: str | None
    started_at: datetime | None
    event_id: uuid.UUID | None
    flagged: bool = False
    children: list[ProcessNode] = []


class UserOut(ORM):
    id: uuid.UUID
    email: str
    display_name: str
    role: str
    is_active: bool
    mfa_enabled: bool
    last_login_at: datetime | None
    created_at: datetime


class AuditOut(ORM):
    id: int
    created_at: datetime
    actor_id: uuid.UUID | None
    actor_email: str | None
    action: str
    resource_type: str
    resource_id: str | None
    outcome: str
    ip_address: str | None
    details: dict[str, Any]
