"""Unit tests for the Sigma subset compiler."""

from __future__ import annotations

import textwrap

import pytest
import yaml

from aegis.detection.sigma import CorrelationRuleDef, DetectionRuleDef, RuleError, compile_rule


def rule(
    detection: str, logsource: str = "product: linux\ncategory: process_creation", extra: str = ""
) -> DetectionRuleDef:
    doc = {
        "title": "Test",
        "id": "test-rule-0001",
        "logsource": yaml.safe_load(logsource),
        "detection": yaml.safe_load(textwrap.dedent(detection)),
        "level": "medium",
        **(yaml.safe_load(extra) or {}),
    }
    compiled = compile_rule(yaml.safe_dump(doc))
    assert isinstance(compiled, DetectionRuleDef)
    return compiled


def proc(**fields: object) -> dict[str, object]:
    base: dict[str, object] = {"category": "process", "action": "start"}
    base.update({f"process.{k}": v for k, v in fields.items()})
    return base


def test_wildcards_are_case_insensitive() -> None:
    r = rule("""
    sel:
      Image: '*/BASH'
    condition: sel
    """)
    assert r.matches(proc(executable="/usr/bin/bash"))
    assert not r.matches(proc(executable="/usr/bin/bashful"))


def test_cased_modifier() -> None:
    r = rule("""
    sel:
      CommandLine|contains|cased: Secret
    condition: sel
    """)
    assert r.matches(proc(command_line="x Secret y"))
    assert not r.matches(proc(command_line="x secret y"))


def test_list_is_or_and_all_modifier_is_and() -> None:
    any_rule = rule("""
    sel:
      CommandLine|contains: [alpha, beta]
    condition: sel
    """)
    all_rule = rule("""
    sel:
      CommandLine|contains|all: [alpha, beta]
    condition: sel
    """)
    assert any_rule.matches(proc(command_line="alpha"))
    assert not all_rule.matches(proc(command_line="alpha"))
    assert all_rule.matches(proc(command_line="beta alpha"))


def test_escaped_wildcard_is_literal() -> None:
    r = rule(r"""
    sel:
      CommandLine: 'a\*b'
    condition: sel
    """)
    assert r.matches(proc(command_line="a*b"))
    assert not r.matches(proc(command_line="axxb"))


def test_condition_grammar() -> None:
    r = rule("""
    sel_a:
      process.name: a
    sel_b:
      process.name: b
    filter:
      User: root
    condition: (1 of sel_* ) and not filter
    """)
    assert r.matches({**proc(name="a"), "user.name": "alice"})
    assert r.matches({**proc(name="b")})
    assert not r.matches({**proc(name="a"), "user.name": "root"})
    assert not r.matches({**proc(name="c")})


def test_all_of_them() -> None:
    r = rule("""
    one:
      process.name: a
    two:
      User: bob
    condition: all of them
    """)
    assert r.matches({**proc(name="a"), "user.name": "bob"})
    assert not r.matches(proc(name="a"))


def test_numeric_comparison_and_cidr() -> None:
    r = rule(
        """
    sel:
      DestinationPort|gte: 1024
      DestinationIp|cidr: 10.0.0.0/8
    condition: sel
    """,
        logsource="product: linux\ncategory: network_connection",
    )
    base = {"category": "network", "action": "connect"}
    assert r.matches({**base, "network.dst_port": 8080, "network.dst_ip": "10.1.2.3"})
    assert not r.matches({**base, "network.dst_port": 80, "network.dst_ip": "10.1.2.3"})
    assert not r.matches({**base, "network.dst_port": 8080, "network.dst_ip": "192.0.2.1"})


def test_null_and_exists() -> None:
    r = rule("""
    sel:
      process.hash_sha256: null
      CommandLine|exists: true
    condition: sel
    """)
    assert r.matches(proc(command_line="x"))
    assert not r.matches(proc(command_line="x", hash_sha256="ab"))
    assert not r.matches(proc())


def test_keywords_search_string_fields() -> None:
    r = rule("""
    keywords:
      - mimikatz
    condition: keywords
    """)
    assert r.matches(proc(command_line="run MIMIKATZ now"))


def test_logsource_filters_category_and_action() -> None:
    r = rule("""
    sel:
      process.name: a
    condition: sel
    """)
    assert not r.matches({"category": "process", "action": "exit", "process.name": "a"})
    assert not r.matches({"category": "file", "action": "start", "process.name": "a"})


@pytest.mark.parametrize(
    ("detection", "message"),
    [
        ("sel:\n  CommandLine|base64offset: x\ncondition: sel", "unsupported modifier"),
        ("sel:\n  RegistryKey: x\ncondition: sel", "unsupported field"),
        ("sel:\n  Image: x\ncondition: sel | count() > 5", "aggregation"),
        ("sel:\n  Image: x\ncondition: other", "unknown selection"),
        ("sel:\n  Image: x\ncondition: (sel", "parentheses"),
        ("sel:\n  Image|re: '('\ncondition: sel", "regular expression"),
        ("sel:\n  Image: x\ncondition: sel\ntimeframe: 5m", "timeframe"),
    ],
)
def test_unsupported_constructs_fail_loudly(detection: str, message: str) -> None:
    content = (
        "title: T\nid: test-rule-0002\nlogsource:\n  product: linux\n"
        "  category: process_creation\ndetection:\n" + textwrap.indent(detection, "  ")
    )
    with pytest.raises(RuleError, match=message):
        compile_rule(content)


def test_unknown_logsource_rejected() -> None:
    with pytest.raises(RuleError, match="logsource"):
        compile_rule(
            "title: T\nid: test-rule-0003\nlogsource: {product: windows, "
            "category: process_creation}\ndetection: {s: {Image: x}, condition: s}"
        )


def test_attack_tags_parsed() -> None:
    r = rule(
        """
    sel:
      Image: x
    condition: sel
    """,
        extra="tags: [attack.execution, attack.t1059.004, attack.g0016]",
    )
    assert r.meta.techniques == ["T1059.004"]
    assert r.meta.tactics == ["execution"]


def test_correlation_rule_parsing() -> None:
    compiled = compile_rule(
        textwrap.dedent("""
    title: Corr
    id: test-corr-0001
    correlation:
      type: value_count
      rules: [base]
      group-by: [SourceIp]
      timespan: 10m
      condition: {field: User, gte: 3}
    level: high
    """)
    )
    assert isinstance(compiled, CorrelationRuleDef)
    assert compiled.group_by == ["network.src_ip"]
    assert compiled.value_field == "user.name"
    assert compiled.timespan.total_seconds() == 600
    assert compiled.threshold_ok(3) and not compiled.threshold_ok(2)
    with pytest.raises(RuleError, match="timespan"):
        compile_rule(
            "title: C\nid: test-corr-0002\ncorrelation: {type: event_count, "
            "rules: [b], timespan: soon, condition: {gte: 1}}"
        )
