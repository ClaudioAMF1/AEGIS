"""Detection engine: evaluates events against rules, evaluates correlations over durable
rule matches and hands results to the alert manager.

Idempotency: a (rule, event) pair is recorded at most once in ``rule_matches``. If an event is
processed again (worker crash before acknowledging, manual replay), the existing match is
detected and no duplicate alert hit is produced.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.detection.fields import flatten
from aegis.detection.registry import RuleSet, registry
from aegis.detection.sigma import CorrelationRuleDef, DetectionRuleDef
from aegis.models import DetectionRule, DetectionRun, Event, RuleMatch
from aegis.observability import metrics
from aegis.services.alerting import AlertManager, AlertOutcome

log = logging.getLogger(__name__)


@dataclass
class DetectionResult:
    events: int = 0
    matches: int = 0
    alerts_created: list[uuid.UUID] = field(default_factory=list)
    alerts_updated: list[uuid.UUID] = field(default_factory=list)
    incidents_touched: set[uuid.UUID] = field(default_factory=set)
    errors: list[str] = field(default_factory=list)


def _group_key(values: dict[str, Any], fields: list[str]) -> tuple[Any, ...]:
    return tuple(values.get(f) for f in fields)


def _max_in_window(times: list[datetime], pivot: datetime, span: timedelta) -> int:
    """Largest number of timestamps inside any window of length ``span`` containing ``pivot``.

    The optimum is reached with the window starting either at a timestamp or at
    ``pivot - span``, so checking those candidates is exact."""
    starts = [t for t in times if pivot - span <= t <= pivot] + [pivot - span]
    return max(sum(1 for t in times if start <= t <= start + span) for start in starts)


def _ordered_sequence(
    by_rule: list[list[tuple[datetime, uuid.UUID]]], span: timedelta, pivot: uuid.UUID
) -> list[uuid.UUID] | None:
    """Find rule1 -> rule2 -> ... -> ruleN occurrences in order within ``span`` that include the
    pivot event. Returns the event ids of the sequence."""
    if any(not occurrences for occurrences in by_rule):
        return None
    for start_time, start_id in sorted(by_rule[0]):
        chain = [start_id]
        current = start_time
        ok = True
        for occurrences in by_rule[1:]:
            candidates = sorted(o for o in occurrences if current <= o[0] <= start_time + span)
            if not candidates:
                ok = False
                break
            current, event_id = candidates[0]
            chain.append(event_id)
        if ok and pivot in chain:
            return chain
    return None


class DetectionEngine:
    def __init__(self, alerts: AlertManager | None = None) -> None:
        self.alerts = alerts or AlertManager()

    def process(self, db: Session, events: Sequence[Event], *, trigger: str) -> DetectionResult:
        started = time.perf_counter()
        ruleset = registry.refresh(db)
        result = DetectionResult(events=len(events))
        run = DetectionRun(
            trigger=trigger, events_evaluated=len(events), rules_evaluated=len(ruleset.enabled)
        )
        db.add(run)
        rule_rows = {
            r.rule_id: r
            for r in db.scalars(select(DetectionRule).where(DetectionRule.is_current.is_(True)))
        }
        for event in sorted(events, key=lambda e: e.occurred_at):
            if event.detection_state == "done" and trigger != "replay":
                continue
            try:
                self._evaluate_event(db, ruleset, rule_rows, event, result)
                event.detection_state = "done"
            except Exception as exc:  # isolate a bad event; keep processing the batch
                log.exception("detection failed for event %s", event.id)
                event.detection_state = "error"
                result.errors.append(f"{event.id}: {type(exc).__name__}: {exc}")
        run.matches = result.matches
        run.alerts_created = len(result.alerts_created)
        run.errors = result.errors[:50]
        run.duration_ms = (time.perf_counter() - started) * 1000
        metrics.DETECTION_LATENCY.observe(run.duration_ms / 1000)
        metrics.RULE_MATCHES.inc(result.matches)
        return result

    # ------------------------------------------------------------------

    def _evaluate_event(
        self,
        db: Session,
        ruleset: RuleSet,
        rule_rows: dict[str, DetectionRule],
        event: Event,
        result: DetectionResult,
    ) -> None:
        fields = flatten(event.payload, event.enrichment)
        for rule_id, rule in ruleset.base.items():
            consumers = [c for c in ruleset.consumers_of(rule) if c in ruleset.enabled]
            if rule_id not in ruleset.enabled and not consumers:
                continue
            if not rule.matches(fields):
                continue
            group_values = {f: fields.get(f) for f in ruleset.correlation_fields(rule)}
            if not self._record_match(db, ruleset, rule, event, group_values):
                continue  # already processed before: idempotent replay
            result.matches += 1
            row = rule_rows.get(rule_id)
            if row is not None:
                row.match_count += 1
                row.last_matched_at = max(
                    row.last_matched_at or event.occurred_at, event.occurred_at
                )
            if rule_id in ruleset.enabled and rule.meta.generate:
                outcome = self.alerts.upsert(
                    db,
                    rule_id=rule_id,
                    rule_version=ruleset.versions.get(rule_id, 1),
                    meta=rule.meta,
                    endpoint_id=event.endpoint_id,
                    events=[event],
                    dedup_scope=str(event.endpoint_id),
                    context={"matched_fields": sorted(rule.used_fields)},
                )
                self._collect(outcome, result)
            for corr_id in consumers:
                self._evaluate_correlation(
                    db, ruleset, rule_rows, corr_id, event, group_values, result
                )

    def _record_match(
        self,
        db: Session,
        ruleset: RuleSet,
        rule: DetectionRuleDef,
        event: Event,
        group_values: dict[str, Any],
    ) -> bool:
        exists = db.scalar(
            select(RuleMatch.id).where(
                RuleMatch.rule_id == rule.meta.rule_id, RuleMatch.event_id == event.id
            )
        )
        if exists is not None:
            return False
        db.add(
            RuleMatch(
                rule_id=rule.meta.rule_id,
                rule_version=ruleset.versions.get(rule.meta.rule_id, 1),
                event_id=event.id,
                endpoint_id=event.endpoint_id,
                occurred_at=event.occurred_at,
                group_values={k: v for k, v in group_values.items() if v is not None},
                is_synthetic=event.is_synthetic,
            )
        )
        db.flush()
        return True

    def _evaluate_correlation(
        self,
        db: Session,
        ruleset: RuleSet,
        rule_rows: dict[str, DetectionRule],
        corr_id: str,
        event: Event,
        group_values: dict[str, Any],
        result: DetectionResult,
    ) -> None:
        corr: CorrelationRuleDef = ruleset.correlations[corr_id]
        referenced = ruleset.referenced_ids(corr)
        key = _group_key(group_values, corr.group_by)
        if any(v is None for v in key):
            return  # cannot group an event that lacks the group-by fields
        window_start = event.occurred_at - corr.timespan
        window_end = event.occurred_at + corr.timespan
        rows = db.scalars(
            select(RuleMatch).where(
                RuleMatch.rule_id.in_(referenced),
                RuleMatch.occurred_at >= window_start,
                RuleMatch.occurred_at <= window_end,
                RuleMatch.is_synthetic.is_(event.is_synthetic),
            )
        ).all()
        rows = [r for r in rows if _group_key(r.group_values, corr.group_by) == key]
        fired_ids: list[uuid.UUID] | None = None
        observed: int | None = None

        if corr.type == "event_count":
            times = [r.occurred_at for r in rows]
            observed = _max_in_window(times, event.occurred_at, corr.timespan)
            if corr.threshold_ok(observed):
                fired_ids = [
                    r.event_id
                    for r in rows
                    if abs(r.occurred_at - event.occurred_at) <= corr.timespan
                ]
        elif corr.type == "value_count":
            near = [r for r in rows if abs(r.occurred_at - event.occurred_at) <= corr.timespan]
            assert corr.value_field is not None
            values = {r.group_values.get(corr.value_field) for r in near} - {None}
            observed = len(values)
            if corr.threshold_ok(observed):
                fired_ids = [r.event_id for r in near]
        elif corr.type == "temporal":
            near = [r for r in rows if abs(r.occurred_at - event.occurred_at) <= corr.timespan]
            seen_rules = {r.rule_id for r in near}
            if set(referenced) <= seen_rules:
                fired_ids = [r.event_id for r in near]
        elif corr.type == "temporal_ordered":
            by_rule = [
                [(r.occurred_at, r.event_id) for r in rows if r.rule_id == rid]
                for rid in referenced
            ]
            fired_ids = _ordered_sequence(by_rule, corr.timespan, event.id)

        if not fired_ids:
            return
        result.matches += 1
        row = rule_rows.get(corr_id)
        if row is not None:
            row.match_count += 1
            row.last_matched_at = event.occurred_at
        evidence = list(db.scalars(select(Event).where(Event.id.in_(set(fired_ids)))))
        group_desc = dict(zip(corr.group_by, key, strict=True))
        outcome = self.alerts.upsert(
            db,
            rule_id=corr_id,
            rule_version=ruleset.versions.get(corr_id, 1),
            meta=corr.meta,
            endpoint_id=event.endpoint_id,
            events=evidence,
            dedup_scope="|".join(f"{k}={v}" for k, v in group_desc.items()) or "global",
            context={
                "correlation_type": corr.type,
                "group_by": group_desc,
                "timespan_seconds": int(corr.timespan.total_seconds()),
                "observed": observed,
                "condition": corr.condition,
                "referenced_rules": referenced,
            },
        )
        self._collect(outcome, result)

    @staticmethod
    def _collect(outcome: AlertOutcome, result: DetectionResult) -> None:
        if outcome.created:
            result.alerts_created.append(outcome.alert.id)
        else:
            result.alerts_updated.append(outcome.alert.id)
        if outcome.incident_id is not None:
            result.incidents_touched.add(outcome.incident_id)


def test_rule_against(content_rule: DetectionRuleDef, payloads: list[dict[str, Any]]) -> list[bool]:
    """Dry-run helper used by the rule tester endpoint and regression tests."""
    return [content_rule.matches(flatten(p)) for p in payloads]
