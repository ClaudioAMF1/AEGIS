"""Loads rule files, versions them in the database and keeps compiled rules in memory."""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis.config import get_settings
from aegis.detection.sigma import (
    CorrelationRuleDef,
    DetectionRuleDef,
    RuleDef,
    RuleError,
    compile_rule,
)
from aegis.models import DetectionRule

log = logging.getLogger(__name__)


@dataclass
class LoadError:
    path: str
    error: str


@dataclass
class LoadedRule:
    definition: RuleDef
    source: str
    path: str


@dataclass
class RuleSet:
    base: dict[str, DetectionRuleDef] = field(default_factory=dict)
    correlations: dict[str, CorrelationRuleDef] = field(default_factory=dict)
    versions: dict[str, int] = field(default_factory=dict)
    enabled: set[str] = field(default_factory=set)
    # rule id/name -> correlation ids that consume it
    consumers: dict[str, list[str]] = field(default_factory=dict)

    def correlation_fields(self, rule: DetectionRuleDef) -> set[str]:
        fields = {"host.hostname"}
        for corr_id in self.consumers_of(rule):
            corr = self.correlations[corr_id]
            fields.update(corr.group_by)
            if corr.value_field:
                fields.add(corr.value_field)
        return fields

    def consumers_of(self, rule: DetectionRuleDef) -> list[str]:
        keys = [rule.meta.rule_id] + ([rule.meta.name] if rule.meta.name else [])
        found: list[str] = []
        for key in keys:
            found.extend(self.consumers.get(key, []))
        return found

    def referenced_ids(self, corr: CorrelationRuleDef) -> list[str]:
        ids = []
        for ref in corr.rules:
            for rule in self.base.values():
                if ref in (rule.meta.rule_id, rule.meta.name):
                    ids.append(rule.meta.rule_id)
        return ids


def discover(rules_dir: str | Path) -> tuple[list[LoadedRule], list[LoadError]]:
    root = Path(rules_dir)
    loaded: list[LoadedRule] = []
    errors: list[LoadError] = []
    seen: dict[str, str] = {}
    for source in ("sigma", "custom"):
        directory = root / source
        if not directory.is_dir():
            continue
        for path in sorted(directory.rglob("*.yml")):
            rel = str(path.relative_to(root))
            try:
                definition = compile_rule(path.read_text(encoding="utf-8"))
            except RuleError as exc:
                errors.append(LoadError(rel, str(exc)))
                continue
            rule_id = definition.meta.rule_id
            if rule_id in seen:
                errors.append(LoadError(rel, f"duplicate rule id also defined in {seen[rule_id]}"))
                continue
            seen[rule_id] = rel
            loaded.append(LoadedRule(definition, source, rel))
    # Correlation references must resolve to known base rules.
    known = set()
    for item in loaded:
        if isinstance(item.definition, DetectionRuleDef):
            known.add(item.definition.meta.rule_id)
            if item.definition.meta.name:
                known.add(item.definition.meta.name)
    valid: list[LoadedRule] = []
    for item in loaded:
        if isinstance(item.definition, CorrelationRuleDef):
            missing = [r for r in item.definition.rules if r not in known]
            if missing:
                errors.append(LoadError(item.path, f"unknown referenced rule(s): {missing}"))
                continue
        valid.append(item)
    return valid, errors


def sync_to_database(db: Session, rules: list[LoadedRule]) -> dict[str, int]:
    """Insert new rules and new versions of changed rules. Returns counters."""
    stats = {"created": 0, "updated": 0, "unchanged": 0}
    for item in rules:
        meta = item.definition.meta
        current = db.scalar(
            select(DetectionRule).where(
                DetectionRule.rule_id == meta.rule_id, DetectionRule.is_current.is_(True)
            )
        )
        if current is not None and current.content_sha256 == meta.sha256:
            stats["unchanged"] += 1
            continue
        enabled = current.enabled if current is not None else meta.status != "deprecated"
        version = 1
        if current is not None:
            current.is_current = False
            latest = db.scalar(
                select(func.max(DetectionRule.version)).where(DetectionRule.rule_id == meta.rule_id)
            )
            version = (latest or 0) + 1
            stats["updated"] += 1
        else:
            stats["created"] += 1
        db.add(
            DetectionRule(
                rule_id=meta.rule_id,
                version=version,
                is_current=True,
                title=meta.title,
                description=meta.description,
                kind="correlation" if isinstance(item.definition, CorrelationRuleDef) else "sigma",
                source=item.source,
                severity=meta.level,
                enabled=enabled,
                generates_alerts=meta.generate,
                attack_techniques=meta.techniques,
                attack_tactics=meta.tactics,
                content=meta.content,
                content_sha256=meta.sha256,
                false_positives=meta.false_positives,
                references=meta.references,
                match_count=current.match_count if current else 0,
                last_matched_at=current.last_matched_at if current else None,
            )
        )
        db.flush()
    return stats


class RuleRegistry:
    """Process-wide cache of compiled rules, refreshed when the database changes."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._ruleset = RuleSet()
        self._fingerprint: tuple[object, ...] | None = None
        self.load_errors: list[LoadError] = []

    def bootstrap(self, db: Session, rules_dir: str | None = None) -> dict[str, int]:
        rules, errors = discover(rules_dir or get_settings().rules_dir)
        self.load_errors = errors
        for error in errors:
            log.warning("rule %s rejected: %s", error.path, error.error)
        stats = sync_to_database(db, rules)
        db.commit()
        self.refresh(db, force=True)
        return stats

    def _db_fingerprint(self, db: Session) -> tuple[object, ...]:
        row = db.execute(
            select(func.count(), func.max(DetectionRule.updated_at)).select_from(DetectionRule)
        ).one()
        enabled = db.scalar(
            select(func.count()).select_from(DetectionRule).where(DetectionRule.enabled.is_(True))
        )
        return (row[0], row[1], enabled)

    def refresh(self, db: Session, *, force: bool = False) -> RuleSet:
        fingerprint = self._db_fingerprint(db)
        if not force and fingerprint == self._fingerprint:
            return self._ruleset
        rows = db.scalars(select(DetectionRule).where(DetectionRule.is_current.is_(True))).all()
        ruleset = RuleSet()
        for row in rows:
            try:
                definition = compile_rule(row.content)
            except RuleError as exc:  # stored rule became invalid (e.g. engine downgrade)
                log.error("stored rule %s v%s invalid: %s", row.rule_id, row.version, exc)
                continue
            ruleset.versions[row.rule_id] = row.version
            if row.enabled:
                ruleset.enabled.add(row.rule_id)
            if isinstance(definition, CorrelationRuleDef):
                ruleset.correlations[row.rule_id] = definition
            else:
                ruleset.base[row.rule_id] = definition
        for corr_id, corr in ruleset.correlations.items():
            for ref in corr.rules:
                ruleset.consumers.setdefault(ref, []).append(corr_id)
        with self._lock:
            self._ruleset = ruleset
            self._fingerprint = fingerprint
        return ruleset

    @property
    def ruleset(self) -> RuleSet:
        return self._ruleset


registry = RuleRegistry()
