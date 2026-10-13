"""Relational data model (PostgreSQL in production, SQLite for zero-infrastructure demos).

Conventions:
* Primary keys are UUIDs, except for the append-only audit log.
* ``occurred_at`` is when something happened on the endpoint, ``ingested_at`` when AEGIS
  received it. Both are always UTC.
* Rows produced by the Demo mode carry ``is_synthetic = True`` and are never mixed
  silently with live telemetry in the UI.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from aegis.db import Base, JSONType, UTCDateTime, utcnow

# ---------------------------------------------------------------------------
# Enumerations (stored as strings so migrations stay portable)
# ---------------------------------------------------------------------------


class RoleName(StrEnum):
    ADMINISTRATOR = "administrator"
    ANALYST = "analyst"
    VIEWER = "viewer"


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


class AlertStatus(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    CLOSED = "closed"


class AlertDisposition(StrEnum):
    UNDETERMINED = "undetermined"
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN = "benign"


class IncidentStatus(StrEnum):
    NEW = "new"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class AgentStatus(StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    REVOKED = "revoked"


class ResponseStatus(StrEnum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    FAILED = "failed"
    REVERTED = "reverted"


def _uuid() -> uuid.UUID:
    return uuid.uuid4()


# ---------------------------------------------------------------------------
# Identity & access
# ---------------------------------------------------------------------------


class Role(Base):
    __tablename__ = "roles"

    name: Mapped[str] = mapped_column(String(32), primary_key=True)
    description: Mapped[str] = mapped_column(String(255))


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(120))
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(ForeignKey("roles.name"), default=RoleName.VIEWER.value)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    mfa_secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_last_used_step: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)


class AuthSession(Base):
    """Server-side session. Only the SHA-256 of the bearer token is stored."""

    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    # "mfa_pending" sessions can only call the MFA verification endpoint.
    stage: Mapped[str] = mapped_column(String(16), default="active")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)

    user: Mapped[User] = relationship()


class LoginAttempt(Base):
    """Sliding-window record used for brute-force protection across API replicas."""

    __tablename__ = "login_attempts"
    __table_args__ = (Index("ix_login_attempts_key_time", "key", "attempted_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    key: Mapped[str] = mapped_column(String(128))
    attempted_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_logs_created", "created_at"),)

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True, index=True)
    actor_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    resource_type: Mapped[str] = mapped_column(String(48))
    resource_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    outcome: Mapped[str] = mapped_column(String(16), default="success")
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)


# ---------------------------------------------------------------------------
# Endpoints & agents
# ---------------------------------------------------------------------------


class Endpoint(Base):
    """A monitored machine. Its identity is the (hostname, synthetic) pair reported by agents."""

    __tablename__ = "endpoints"
    __table_args__ = (UniqueConstraint("hostname", "is_synthetic", name="uq_endpoint_host"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    hostname: Mapped[str] = mapped_column(String(255))
    os: Mapped[str | None] = mapped_column(String(120), nullable=True)
    ip_addresses: Mapped[list[str]] = mapped_column(JSONType, default=list)
    criticality: Mapped[str] = mapped_column(String(16), default="medium")
    tags: Mapped[list[str]] = mapped_column(JSONType, default=list)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    isolation_state: Mapped[str] = mapped_column(String(24), default="none")


class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(120))
    endpoint_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("endpoints.id", ondelete="SET NULL"), nullable=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    token_prefix: Mapped[str] = mapped_column(String(12))
    status: Mapped[str] = mapped_column(String(16), default=AgentStatus.PENDING.value)
    version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    config: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    last_seq: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    events_received: Mapped[int] = mapped_column(BigInteger, default=0)
    events_duplicated: Mapped[int] = mapped_column(BigInteger, default=0)
    events_rejected: Mapped[int] = mapped_column(BigInteger, default=0)
    buffer_depth: Mapped[int | None] = mapped_column(Integer, nullable=True)

    endpoint: Mapped[Endpoint | None] = relationship()


# ---------------------------------------------------------------------------
# Telemetry
# ---------------------------------------------------------------------------


class Event(Base):
    """Normalised security event. ``event_id`` is generated by the producer and is the
    idempotency key: re-sent events are acknowledged but never stored twice."""

    __tablename__ = "events"
    __table_args__ = (
        Index("ix_events_occurred", "occurred_at"),
        Index("ix_events_endpoint_occurred", "endpoint_id", "occurred_at"),
        Index("ix_events_category_action", "category", "action"),
        Index("ix_events_process", "endpoint_id", "process_pid"),
        Index("ix_events_ingested", "ingested_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    schema_version: Mapped[str] = mapped_column(String(8))
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime)
    ingested_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    endpoint_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("endpoints.id", ondelete="CASCADE"))
    agent_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("agents.id", ondelete="SET NULL"), nullable=True
    )
    seq: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    category: Mapped[str] = mapped_column(String(24))
    action: Mapped[str] = mapped_column(String(32))
    hostname: Mapped[str] = mapped_column(String(255))
    user_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    process_pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    process_ppid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    process_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    src_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    summary: Mapped[str] = mapped_column(String(512))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONType)
    enrichment: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    dataset: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    detection_state: Mapped[str] = mapped_column(String(12), default="pending", index=True)


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


class DetectionRule(Base):
    __tablename__ = "detection_rules"
    __table_args__ = (UniqueConstraint("rule_id", "version", name="uq_rule_version"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    version: Mapped[int] = mapped_column(Integer)
    is_current: Mapped[bool] = mapped_column(Boolean, default=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    kind: Mapped[str] = mapped_column(String(16))  # "sigma" | "correlation"
    source: Mapped[str] = mapped_column(String(16))  # "sigma" | "custom"
    severity: Mapped[str] = mapped_column(String(16))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    generates_alerts: Mapped[bool] = mapped_column(Boolean, default=True)
    attack_techniques: Mapped[list[str]] = mapped_column(JSONType, default=list)
    attack_tactics: Mapped[list[str]] = mapped_column(JSONType, default=list)
    content: Mapped[str] = mapped_column(Text)
    content_sha256: Mapped[str] = mapped_column(String(64))
    false_positives: Mapped[list[str]] = mapped_column(JSONType, default=list)
    references: Mapped[list[str]] = mapped_column(JSONType, default=list)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)
    match_count: Mapped[int] = mapped_column(BigInteger, default=0)
    last_matched_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class RuleMatch(Base):
    """Every event that satisfied a rule. Correlation rules are evaluated over these rows,
    which keeps windowed state durable across restarts and tolerant to out-of-order events."""

    __tablename__ = "rule_matches"
    __table_args__ = (
        UniqueConstraint("rule_id", "event_id", name="uq_rule_match"),
        Index("ix_rule_matches_rule_time", "rule_id", "occurred_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    rule_id: Mapped[str] = mapped_column(String(64))
    rule_version: Mapped[int] = mapped_column(Integer)
    event_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"))
    endpoint_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime)
    group_values: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)


class DetectionRun(Base):
    __tablename__ = "detection_runs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    duration_ms: Mapped[float] = mapped_column(Float, default=0.0)
    trigger: Mapped[str] = mapped_column(String(16))  # inline | worker | replay | test
    events_evaluated: Mapped[int] = mapped_column(Integer, default=0)
    rules_evaluated: Mapped[int] = mapped_column(Integer, default=0)
    matches: Mapped[int] = mapped_column(Integer, default=0)
    alerts_created: Mapped[int] = mapped_column(Integer, default=0)
    errors: Mapped[list[str]] = mapped_column(JSONType, default=list)


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_status_created", "status", "created_at"),
        Index("ix_alerts_dedup", "dedup_key", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    rule_version: Mapped[int] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(16), default=AlertStatus.OPEN.value)
    disposition: Mapped[str] = mapped_column(String(24), default=AlertDisposition.UNDETERMINED)
    endpoint_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("endpoints.id", ondelete="CASCADE"))
    dedup_key: Mapped[str] = mapped_column(String(128))
    hit_count: Mapped[int] = mapped_column(Integer, default=1)
    first_event_at: Mapped[datetime] = mapped_column(UTCDateTime)
    last_event_at: Mapped[datetime] = mapped_column(UTCDateTime)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)
    triaged_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    triaged_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    attack_techniques: Mapped[list[str]] = mapped_column(JSONType, default=list)
    attack_tactics: Mapped[list[str]] = mapped_column(JSONType, default=list)
    context: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True
    )
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)

    endpoint: Mapped[Endpoint] = relationship()


class AlertEvent(Base):
    __tablename__ = "alert_events"

    alert_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True
    )
    event_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("events.id", ondelete="CASCADE"), primary_key=True
    )


# ---------------------------------------------------------------------------
# Investigation
# ---------------------------------------------------------------------------


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint(
            "status in ('new','investigating','contained','resolved','false_positive')",
            name="ck_incident_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    number: Mapped[int] = mapped_column(Integer, unique=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(24), default=IncidentStatus.NEW.value, index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime)
    ended_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    detected_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    first_triaged_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    assignee_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    attack_techniques: Mapped[list[str]] = mapped_column(JSONType, default=list)
    attack_tactics: Mapped[list[str]] = mapped_column(JSONType, default=list)
    endpoint_ids: Mapped[list[str]] = mapped_column(JSONType, default=list)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)

    assignee: Mapped[User | None] = relationship()


class IncidentEvent(Base):
    __tablename__ = "incident_events"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True
    )
    event_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("events.id", ondelete="CASCADE"), primary_key=True
    )
    added_by: Mapped[str] = mapped_column(String(16), default="detection")  # or "analyst"
    added_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[str] = mapped_column(String(24))  # event | alert | indicator | note
    reference: Mapped[str | None] = mapped_column(String(64), nullable=True)
    label: Mapped[str] = mapped_column(String(255))
    data: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class Investigation(Base):
    """Investigation journal: comments, status changes, assignments, actions."""

    __tablename__ = "investigations"
    __table_args__ = (Index("ix_investigations_incident_time", "incident_id", "created_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"))
    entry_type: Mapped[str] = mapped_column(String(24))  # comment | change | action | system
    author_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    author_name: Mapped[str] = mapped_column(String(120))
    body: Mapped[str] = mapped_column(Text, default="")
    changes: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


# ---------------------------------------------------------------------------
# Threat intelligence
# ---------------------------------------------------------------------------


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"
    __table_args__ = (UniqueConstraint("type", "value", "source", name="uq_indicator"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    type: Mapped[str] = mapped_column(String(16))  # ipv4 | ipv6 | domain | sha256 | cidr
    value: Mapped[str] = mapped_column(String(255), index=True)
    source: Mapped[str] = mapped_column(String(64))
    confidence: Mapped[int] = mapped_column(Integer, default=50)  # 0..100
    severity: Mapped[str] = mapped_column(String(16), default=Severity.MEDIUM.value)
    description: Mapped[str] = mapped_column(Text, default="")
    tags: Mapped[list[str]] = mapped_column(JSONType, default=list)
    license: Mapped[str | None] = mapped_column(String(64), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    hits: Mapped[int] = mapped_column(Integer, default=0)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)


class IntelLookup(Base):
    """Cache of external reputation lookups with provenance."""

    __tablename__ = "intel_lookups"
    __table_args__ = (UniqueConstraint("provider", "indicator", name="uq_intel_lookup"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    provider: Mapped[str] = mapped_column(String(32))
    indicator: Mapped[str] = mapped_column(String(255))
    verdict: Mapped[str] = mapped_column(String(24))
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    data: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    queried_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)


# ---------------------------------------------------------------------------
# Response, reports, simulations, assistant
# ---------------------------------------------------------------------------


class ResponseAction(Base):
    __tablename__ = "response_actions"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    action_type: Mapped[str] = mapped_column(String(48))
    target_type: Mapped[str] = mapped_column(String(24))
    target_id: Mapped[str] = mapped_column(String(64))
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True
    )
    status: Mapped[str] = mapped_column(String(16), default=ResponseStatus.PROPOSED.value)
    justification: Mapped[str] = mapped_column(Text, default="")
    impact_preview: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    result: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    reversible: Mapped[bool] = mapped_column(Boolean, default=False)
    requested_by: Mapped[uuid.UUID] = mapped_column(Uuid)
    approved_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    requested_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    executed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    reverted_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    title: Mapped[str] = mapped_column(String(255))
    kind: Mapped[str] = mapped_column(String(24))  # overview | incident
    period_start: Mapped[datetime] = mapped_column(UTCDateTime)
    period_end: Mapped[datetime] = mapped_column(UTCDateTime)
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True
    )
    include_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    content: Mapped[dict[str, Any]] = mapped_column(JSONType)
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class Simulation(Base):
    __tablename__ = "simulations"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    scenario: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(16))  # running | completed | failed | reset
    started_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    events_sent: Mapped[int] = mapped_column(Integer, default=0)
    alerts_created: Mapped[int] = mapped_column(Integer, default=0)
    details: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)


class AssistantQuery(Base):
    __tablename__ = "assistant_queries"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, index=True)
    incident_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True, index=True)
    task: Mapped[str] = mapped_column(String(32))
    question: Mapped[str] = mapped_column(Text)
    engine: Mapped[str] = mapped_column(String(48))
    response: Mapped[dict[str, Any]] = mapped_column(JSONType)
    evidence_ids: Mapped[list[str]] = mapped_column(JSONType, default=list)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
