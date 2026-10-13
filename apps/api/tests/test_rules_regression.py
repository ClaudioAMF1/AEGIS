"""Regression suite for every rule that has cases in rules/tests. Each case is a partial ACE
event; it is validated against the contract before evaluation, so cases cannot drift from
the real schema."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from aegis.detection.fields import flatten
from aegis.detection.registry import discover
from aegis.detection.sigma import DetectionRuleDef
from aegis.events.contract import EventIn
from tests.conftest import ROOT, event

RULES = {r.definition.meta.rule_id: r.definition for r in discover(ROOT / "rules")[0]}
CASES = sorted((ROOT / "rules" / "tests").glob("*.yml"))


def _complete(partial: dict[str, Any]) -> dict[str, Any]:
    sections = {k: v for k, v in partial.items() if k not in {"category", "action"}}
    return event(
        category=partial.get("category", "process"),
        action=partial.get("action", "start"),
        **sections,
    )


def _evaluate(rule: DetectionRuleDef, partial: dict[str, Any]) -> bool:
    payload = EventIn.model_validate(_complete(partial)).model_dump(mode="json", exclude_none=True)
    return rule.matches(flatten(payload))


def test_all_rules_load_without_errors() -> None:
    _, errors = discover(ROOT / "rules")
    assert errors == []
    assert len(RULES) >= 20


def test_every_base_rule_has_regression_cases() -> None:
    covered = {yaml.safe_load(p.read_text())["rule"] for p in CASES}
    base = {rid for rid, r in RULES.items() if isinstance(r, DetectionRuleDef)}
    # intel rules depend on enrichment and are covered by integration tests
    missing = base - covered - {"aegis-intel-indicator-match", "aegis-intel-indicator-auth"}
    assert not missing, f"rules without regression cases: {sorted(missing)}"


@pytest.mark.parametrize("path", CASES, ids=lambda p: Path(p).stem)
def test_rule_cases(path: Path) -> None:
    spec = yaml.safe_load(path.read_text())
    rule = RULES[spec["rule"]]
    assert isinstance(rule, DetectionRuleDef)
    for case in spec.get("match", []):
        assert _evaluate(rule, case), f"expected match: {case}"
    for case in spec.get("no_match", []):
        assert not _evaluate(rule, case), f"unexpected match: {case}"
