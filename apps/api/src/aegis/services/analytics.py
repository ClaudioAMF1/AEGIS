"""Security metrics. Every metric carries its definition, data source and reference period so
numbers on the dashboard are traceable and never presented without context."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta
from statistics import median
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis.db import utcnow
from aegis.models import (
    Agent,
    AgentStatus,
    Alert,
    AlertDisposition,
    AlertStatus,
    DetectionRule,
    Endpoint,
    Event,
    Incident,
    IncidentStatus,
)
from aegis.routers.common import scope_clause
from aegis.schemas import Scope


@dataclass
class Metric:
    key: str
    label: str
    value: float | int | None
    unit: str
    definition: str
    source: str

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


def _pct(numerator: int, denominator: int) -> float | None:
    return round(100.0 * numerator / denominator, 1) if denominator else None


def overview(db: Session, scope: Scope, start: datetime, end: datetime) -> dict[str, Any]:
    ev = [scope_clause(Event.is_synthetic, scope), Event.occurred_at.between(start, end)]
    al = [scope_clause(Alert.is_synthetic, scope), Alert.created_at.between(start, end)]
    inc = [scope_clause(Incident.is_synthetic, scope)]

    events_total = db.scalar(select(func.count()).select_from(Event).where(*ev)) or 0
    last_minute = (
        db.scalar(
            select(func.count())
            .select_from(Event)
            .where(
                scope_clause(Event.is_synthetic, scope),
                Event.ingested_at >= utcnow() - timedelta(minutes=1),
            )
        )
        or 0
    )
    endpoints = (
        db.scalar(
            select(func.count())
            .select_from(Endpoint)
            .where(scope_clause(Endpoint.is_synthetic, scope))
        )
        or 0
    )
    online = (
        db.scalar(
            select(func.count())
            .select_from(Endpoint)
            .where(
                scope_clause(Endpoint.is_synthetic, scope),
                Endpoint.last_seen_at >= utcnow() - timedelta(minutes=2),
            )
        )
        or 0
    )
    open_alerts = (
        db.scalar(
            select(func.count())
            .select_from(Alert)
            .where(
                scope_clause(Alert.is_synthetic, scope), Alert.status != AlertStatus.CLOSED.value
            )
        )
        or 0
    )
    alerts_by_sev = dict(
        db.execute(select(Alert.severity, func.count()).where(*al).group_by(Alert.severity)).all()
    )
    open_incidents = dict(
        db.execute(
            select(Incident.severity, func.count())
            .where(
                *inc,
                Incident.status.in_(
                    [
                        IncidentStatus.NEW.value,
                        IncidentStatus.INVESTIGATING.value,
                        IncidentStatus.CONTAINED.value,
                    ]
                ),
            )
            .group_by(Incident.severity)
        ).all()
    )
    agents = db.execute(
        select(Agent.status, func.count())
        .where(scope_clause(Agent.is_synthetic, scope))
        .group_by(Agent.status)
    ).all()
    rules_enabled = (
        db.scalar(
            select(func.count())
            .select_from(DetectionRule)
            .where(DetectionRule.is_current.is_(True), DetectionRule.enabled.is_(True))
        )
        or 0
    )

    period = {"start": start.isoformat(), "end": end.isoformat()}
    metrics = [
        Metric(
            "endpoints",
            "Monitored endpoints",
            endpoints,
            "count",
            "Distinct hosts that have reported telemetry.",
            "endpoints table",
        ),
        Metric(
            "endpoints_online",
            "Endpoints online",
            online,
            "count",
            "Hosts that reported within the last 2 minutes.",
            "endpoints.last_seen_at",
        ),
        Metric(
            "events_per_second",
            "Events / second",
            round(last_minute / 60, 2),
            "eps",
            "Events ingested during the last 60 seconds divided by 60.",
            "events.ingested_at",
        ),
        Metric(
            "events_period",
            "Events in period",
            events_total,
            "count",
            "Events whose occurrence time falls in the period.",
            "events.occurred_at",
        ),
        Metric(
            "open_alerts",
            "Open alerts",
            open_alerts,
            "count",
            "Alerts not in the closed state (any time).",
            "alerts.status",
        ),
        Metric(
            "rules_enabled",
            "Rules enabled",
            rules_enabled,
            "count",
            "Current rule versions that are enabled.",
            "detection_rules",
        ),
    ]
    return {
        "scope": scope.value,
        "period": period,
        "metrics": [m.as_dict() for m in metrics],
        "alerts_by_severity": alerts_by_sev,
        "open_incidents_by_severity": open_incidents,
        "agents_by_status": dict(agents),
        "ingestion": {"agents_active": dict(agents).get(AgentStatus.ACTIVE.value, 0)},
    }


def analytics(db: Session, scope: Scope, start: datetime, end: datetime) -> dict[str, Any]:
    alerts = db.scalars(
        select(Alert).where(
            scope_clause(Alert.is_synthetic, scope), Alert.created_at.between(start, end)
        )
    ).all()
    incidents = db.scalars(
        select(Incident).where(
            scope_clause(Incident.is_synthetic, scope), Incident.detected_at.between(start, end)
        )
    ).all()
    event_rows = db.execute(
        select(Event.hostname, Event.category, func.count())
        .where(scope_clause(Event.is_synthetic, scope), Event.occurred_at.between(start, end))
        .group_by(Event.hostname, Event.category)
    ).all()
    rules = db.scalars(select(DetectionRule).where(DetectionRule.is_current.is_(True))).all()

    by_host: Counter[str] = Counter()
    by_category: Counter[str] = Counter()
    for host, category, count in event_rows:
        by_host[host] += count
        by_category[category] += count

    # Time to detect: detection (alert creation) minus first evidence occurrence. For demo
    # replays occurrence times are historical, so TTD is only meaningful for live data.
    ttd = [
        (a.created_at - a.first_event_at).total_seconds()
        for a in alerts
        if not a.is_synthetic and a.created_at >= a.first_event_at
    ]
    ttt = [
        (a.triaged_at - a.created_at).total_seconds() for a in alerts if a.triaged_at is not None
    ]
    labelled = [a for a in alerts if a.disposition != AlertDisposition.UNDETERMINED.value]
    false_pos = [a for a in labelled if a.disposition == AlertDisposition.FALSE_POSITIVE.value]
    rule_hits = Counter(a.rule_id for a in alerts)
    titles = {r.rule_id: r.title for r in rules}

    techniques = {t for r in rules if r.enabled for t in r.attack_techniques}
    tactics = {t for r in rules if r.enabled for t in r.attack_tactics}
    days = max(1, (end - start).days)
    timeline: dict[str, Counter[str]] = {}
    for a in alerts:
        bucket = (
            a.created_at.date().isoformat() if days > 2 else a.created_at.strftime("%Y-%m-%dT%H:00")
        )
        timeline.setdefault(bucket, Counter())[a.severity] += 1

    def stat(values: list[float]) -> dict[str, float | None]:
        return {
            "median": round(median(values), 1) if values else None,
            "mean": round(sum(values) / len(values), 1) if values else None,
            "samples": len(values),
        }

    return {
        "scope": scope.value,
        "period": {"start": start.isoformat(), "end": end.isoformat()},
        "definitions": {
            "events_by_host": "Count of events per host with occurrence time in the period.",
            "alerts_by_severity": "Alerts created in the period grouped by rule severity.",
            "top_rules": "Rules ordered by number of alerts created in the period.",
            "false_positive_rate": "Alerts labelled false_positive / alerts with any label "
            "(undetermined alerts excluded). Source: alerts.disposition.",
            "time_to_detect": "alerts.created_at - alerts.first_event_at in seconds. Live "
            "data only (demo replays use historical timestamps).",
            "time_to_triage": "alerts.triaged_at - alerts.created_at in seconds.",
            "coverage": "Distinct ATT&CK techniques/tactics referenced by enabled rules. "
            "Indicates intent of coverage, not validated detection efficacy.",
        },
        "events_by_host": dict(by_host.most_common(20)),
        "events_by_category": dict(by_category),
        "alerts_by_severity": dict(Counter(a.severity for a in alerts)),
        "alerts_timeline": [{"bucket": k, **v} for k, v in sorted(timeline.items())],
        "top_rules": [
            {"rule_id": r, "title": titles.get(r, r), "alerts": n}
            for r, n in rule_hits.most_common(10)
        ],
        "false_positive_rate": {
            "value": _pct(len(false_pos), len(labelled)),
            "labelled": len(labelled),
            "false_positives": len(false_pos),
        },
        "time_to_detect_seconds": stat(ttd),
        "time_to_triage_seconds": stat(ttt),
        "incidents": {
            "opened": len(incidents),
            "resolved": sum(1 for i in incidents if i.status == IncidentStatus.RESOLVED.value),
            "false_positive": sum(
                1 for i in incidents if i.status == IncidentStatus.FALSE_POSITIVE.value
            ),
        },
        "coverage": {
            "techniques": sorted(techniques),
            "tactics": sorted(tactics),
            "rules_enabled": sum(1 for r in rules if r.enabled),
            "rules_total": len(rules),
        },
    }
