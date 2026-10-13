"""Compiler for the supported subset of the Sigma rule format.

Supported (documented in docs/detection.md):

* ``logsource`` combinations listed in :data:`aegis.detection.fields.LOGSOURCE_MAP`.
* Detection items: maps (AND of fields), lists of maps (OR), keyword lists.
* Values: strings with ``*``/``?`` wildcards, numbers, booleans, ``null``; lists mean OR.
* Modifiers: ``contains``, ``startswith``, ``endswith``, ``all``, ``re``, ``cidr``,
  ``gt``, ``gte``, ``lt``, ``lte``, ``exists``, ``cased``.
* Conditions: ``and``, ``or``, ``not``, parentheses, ``1 of x*``, ``all of x*``,
  ``1 of them``, ``all of them``.
* Correlation rules (Sigma correlation specification): ``event_count``, ``value_count``,
  ``temporal`` and ``temporal_ordered`` with ``group-by``, ``timespan`` and ``condition``.

Anything else (``base64offset``, ``windash``, field references, aggregation pipes ``|``
in conditions, ``near``…) raises :class:`RuleError` at load time. Rules never fail silently.
"""

from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

import yaml

from aegis.detection.fields import LOGSOURCE_MAP
from aegis.detection.fields import resolve_field as _resolve_native
from aegis.models import Severity

Fields = dict[str, Any]
Matcher = Callable[[Fields], bool]

_SUPPORTED_MODIFIERS = {
    "contains",
    "startswith",
    "endswith",
    "all",
    "re",
    "cidr",
    "gt",
    "gte",
    "lt",
    "lte",
    "exists",
    "cased",
}
_LEVELS = {s.value for s in Severity}
_TECHNIQUE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_TIMESPAN = re.compile(r"^(\d+)([smhd])$")


class RuleError(ValueError):
    """Raised when a rule uses unsupported or invalid Sigma constructs."""


def resolve_field(name: str) -> str:
    try:
        return _resolve_native(name)
    except ValueError as exc:
        raise RuleError(str(exc)) from exc


@dataclass(frozen=True)
class RuleMeta:
    rule_id: str
    name: str | None
    title: str
    description: str
    level: str
    status: str
    tags: list[str]
    references: list[str]
    false_positives: list[str]
    author: str | None
    version: int
    generate: bool
    content: str

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content.encode()).hexdigest()

    @property
    def techniques(self) -> list[str]:
        found = []
        for tag in self.tags:
            match = _TECHNIQUE.match(tag)
            if match:
                found.append(match.group(1).upper())
        return found

    @property
    def tactics(self) -> list[str]:
        return [
            tag.split(".", 1)[1].replace("_", "-")
            for tag in self.tags
            if tag.lower().startswith("attack.")
            and not _TECHNIQUE.match(tag)
            and not tag.lower().startswith("attack.g")
            and not tag.lower().startswith("attack.s")
        ]


@dataclass
class DetectionRuleDef:
    meta: RuleMeta
    category: str
    actions: frozenset[str]
    matcher: Matcher
    used_fields: set[str] = field(default_factory=set)

    def matches(self, fields: Fields) -> bool:
        if fields.get("category") != self.category or fields.get("action") not in self.actions:
            return False
        return self.matcher(fields)


@dataclass
class CorrelationRuleDef:
    meta: RuleMeta
    type: str
    rules: list[str]
    group_by: list[str]
    timespan: timedelta
    condition: dict[str, int]
    value_field: str | None

    def threshold_ok(self, value: int) -> bool:
        ops = {
            "gt": lambda a, b: a > b,
            "gte": lambda a, b: a >= b,
            "lt": lambda a, b: a < b,
            "lte": lambda a, b: a <= b,
            "eq": lambda a, b: a == b,
        }
        return all(ops[op](value, bound) for op, bound in self.condition.items())


RuleDef = DetectionRuleDef | CorrelationRuleDef


# ---------------------------------------------------------------------------
# Value matching
# ---------------------------------------------------------------------------


def _as_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _wildcard_regex(pattern: str, cased: bool) -> re.Pattern[str]:
    # Sigma: '*' and '?' are wildcards, '\' escapes them.
    out = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern) and pattern[i + 1] in "*?\\":
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        out.append(".*" if ch == "*" else "." if ch == "?" else re.escape(ch))
        i += 1
    return re.compile("^" + "".join(out) + "$", 0 if cased else re.IGNORECASE | re.DOTALL)


_COMPARATORS: dict[str, Callable[[float], Callable[[float], bool]]] = {
    "gt": lambda bound: lambda a: a > bound,
    "gte": lambda bound: lambda a: a >= bound,
    "lt": lambda bound: lambda a: a < bound,
    "lte": lambda bound: lambda a: a <= bound,
}


def _value_matcher(raw: Any, modifiers: list[str]) -> Callable[[Any], bool]:
    cased = "cased" in modifiers
    if "exists" in modifiers:
        expected = bool(raw)
        return lambda v: (v is not None) == expected
    if raw is None:
        return lambda v: v is None
    for op in ("gt", "gte", "lt", "lte"):
        if op in modifiers:
            if isinstance(raw, bool) or not isinstance(raw, (int, float)):
                raise RuleError(f"modifier '{op}' requires a number")
            bound = float(raw)
            compare = _COMPARATORS[op](bound)

            def numeric(v: Any, compare: Callable[[float], bool] = compare) -> bool:
                try:
                    return v is not None and not isinstance(v, bool) and compare(float(v))
                except (TypeError, ValueError):
                    return False

            return numeric
    if "cidr" in modifiers:
        try:
            network = ipaddress.ip_network(str(raw), strict=False)
        except ValueError as exc:
            raise RuleError(f"invalid cidr '{raw}'") from exc

        def in_cidr(v: Any) -> bool:
            try:
                return v is not None and ipaddress.ip_address(str(v)) in network
            except ValueError:
                return False

        return in_cidr
    if "re" in modifiers:
        try:
            regex = re.compile(str(raw), 0 if cased else re.IGNORECASE)
        except re.error as exc:
            raise RuleError(f"invalid regular expression: {exc}") from exc
        return lambda v: v is not None and regex.search(_as_text(v)) is not None
    if isinstance(raw, (int, float)) and not isinstance(raw, bool):
        return lambda v: v is not None and not isinstance(v, bool) and _num_eq(v, raw)
    text = _as_text(raw)
    if "contains" in modifiers:
        text = f"*{text}*"
    elif "startswith" in modifiers:
        text = f"{text}*"
    elif "endswith" in modifiers:
        text = f"*{text}"
    regex = _wildcard_regex(text, cased)
    return lambda v: v is not None and regex.match(_as_text(v)) is not None


def _num_eq(value: Any, expected: float) -> bool:
    try:
        return float(value) == float(expected)
    except (TypeError, ValueError):
        return False


def _field_matcher(key: str, raw: Any, used: set[str]) -> Matcher:
    name, *modifiers = key.split("|")
    unsupported = [m for m in modifiers if m not in _SUPPORTED_MODIFIERS]
    if unsupported:
        raise RuleError(f"unsupported modifier(s): {', '.join(unsupported)}")
    target = resolve_field(name)
    used.add(target)
    values = raw if isinstance(raw, list) else [raw]
    if not values:
        raise RuleError(f"field '{name}' has an empty value list")
    checks = [_value_matcher(v, modifiers) for v in values]
    require_all = "all" in modifiers

    def match(fields: Fields) -> bool:
        actual = fields.get(target)
        results = (check(actual) for check in checks)
        return all(results) if require_all else any(results)

    return match


def _keyword_matcher(keywords: list[Any]) -> Matcher:
    checks = [_value_matcher(f"*{_as_text(k)}*", []) for k in keywords]

    def match(fields: Fields) -> bool:
        texts = [v for v in fields.values() if isinstance(v, str)]
        return any(check(t) for check in checks for t in texts)

    return match


def _selection_matcher(name: str, definition: Any, used: set[str]) -> Matcher:
    if isinstance(definition, dict):
        if not definition:
            raise RuleError(f"selection '{name}' is empty")
        parts = [_field_matcher(str(k), v, used) for k, v in definition.items()]
        return lambda f: all(p(f) for p in parts)
    if isinstance(definition, list) and definition:
        if all(isinstance(item, dict) for item in definition):
            alternatives = [_selection_matcher(name, item, used) for item in definition]
            return lambda f: any(a(f) for a in alternatives)
        if all(not isinstance(item, (dict, list)) for item in definition):
            return _keyword_matcher(definition)
    raise RuleError(f"selection '{name}' has an unsupported structure")


# ---------------------------------------------------------------------------
# Condition parser (recursive descent)
# ---------------------------------------------------------------------------

_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*]+)")


def _tokenize(condition: str) -> list[str]:
    if "|" in condition:
        raise RuleError(
            "aggregation expressions in conditions are not supported; "
            "use a correlation rule instead"
        )
    tokens: list[str] = []
    pos = 0
    condition = condition.strip()
    while pos < len(condition):
        match = _TOKEN.match(condition, pos)
        if not match:
            raise RuleError(f"invalid condition near '{condition[pos:]}'")
        tokens.append(match.group(1))
        pos = match.end()
    return tokens


class _ConditionParser:
    def __init__(self, tokens: list[str], selections: dict[str, Matcher]) -> None:
        self.tokens = tokens
        self.pos = 0
        self.selections = selections

    def parse(self) -> Matcher:
        node = self._or()
        if self.pos != len(self.tokens):
            raise RuleError(f"unexpected tok '{self.tokens[self.pos]}' in condition")
        return node

    def _peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _take(self) -> str:
        tok = self._peek()
        if tok is None:
            raise RuleError("condition ended unexpectedly")
        self.pos += 1
        return tok

    def _or(self) -> Matcher:
        left = self._and()
        while (self._peek() or "").lower() == "or":
            self._take()
            right = self._and()
            left = (lambda a, b: lambda f: a(f) or b(f))(left, right)
        return left

    def _and(self) -> Matcher:
        left = self._not()
        while (self._peek() or "").lower() == "and":
            self._take()
            right = self._not()
            left = (lambda a, b: lambda f: a(f) and b(f))(left, right)
        return left

    def _not(self) -> Matcher:
        if (self._peek() or "").lower() == "not":
            self._take()
            inner = self._not()
            return lambda f: not inner(f)
        return self._atom()

    def _atom(self) -> Matcher:
        tok = self._take()
        if tok == "(":
            node = self._or()
            if self._peek() != ")":
                raise RuleError("unbalanced parentheses in condition")
            self._take()
            return node
        if tok in {"1", "all"} and (self._peek() or "").lower() == "of":
            self._take()
            target = self._take()
            names = self._resolve_group(target)
            parts = [self.selections[n] for n in names]
            if tok == "1":
                return lambda f: any(p(f) for p in parts)
            return lambda f: all(p(f) for p in parts)
        if tok.lower() in {"and", "or", "of", ")"}:
            raise RuleError(f"unexpected '{tok}' in condition")
        if tok not in self.selections:
            raise RuleError(f"condition references unknown selection '{tok}'")
        return self.selections[tok]

    def _resolve_group(self, target: str) -> list[str]:
        if target == "them":
            names = [n for n in self.selections if not n.startswith("_")]
        else:
            names = [n for n in self.selections if fnmatch.fnmatchcase(n, target)]
        if not names:
            raise RuleError(f"'{target}' does not match any selection")
        return names


# ---------------------------------------------------------------------------
# Rule loading
# ---------------------------------------------------------------------------


def _meta(doc: dict[str, Any], content: str) -> RuleMeta:
    rule_id = str(doc.get("id") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9-]{8,64}", rule_id):
        raise RuleError("rule 'id' is required (8-64 chars, letters, digits, '-')")
    title = str(doc.get("title") or "").strip()
    if not title:
        raise RuleError("rule 'title' is required")
    level = str(doc.get("level") or "medium").lower()
    if level not in _LEVELS:
        raise RuleError(f"invalid level '{level}'")
    aegis_ext = doc.get("aegis") or {}
    return RuleMeta(
        rule_id=rule_id,
        name=doc.get("name"),
        title=title,
        description=str(doc.get("description") or "").strip(),
        level=level,
        status=str(doc.get("status") or "experimental"),
        tags=[str(t).lower() for t in doc.get("tags") or []],
        references=[str(r) for r in doc.get("references") or []],
        false_positives=[str(r) for r in doc.get("falsepositives") or []],
        author=doc.get("author"),
        version=int(aegis_ext.get("version", 1)),
        generate=bool(doc.get("generate", True)),
        content=content,
    )


def _parse_timespan(value: Any) -> timedelta:
    match = _TIMESPAN.match(str(value).strip())
    if not match:
        raise RuleError(f"invalid timespan '{value}' (expected e.g. 30s, 5m, 1h, 1d)")
    amount, unit = int(match.group(1)), match.group(2)
    return timedelta(**{{"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}[unit]: amount})


def compile_rule(content: str) -> RuleDef:
    try:
        doc = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise RuleError(f"invalid YAML: {exc}") from exc
    if not isinstance(doc, dict):
        raise RuleError("rule must be a YAML mapping")
    meta = _meta(doc, content)

    if "correlation" in doc:
        corr = doc["correlation"] or {}
        ctype = corr.get("type")
        if ctype not in {"event_count", "value_count", "temporal", "temporal_ordered"}:
            raise RuleError(f"unsupported correlation type '{ctype}'")
        rules = [str(r) for r in corr.get("rules") or []]
        if not rules:
            raise RuleError("correlation requires 'rules'")
        group_by = [resolve_field(str(g)) for g in corr.get("group-by") or []]
        condition_raw = corr.get("condition") or {}
        value_field = None
        condition: dict[str, int] = {}
        if ctype in {"event_count", "value_count"}:
            if not isinstance(condition_raw, dict) or not condition_raw:
                raise RuleError("event_count/value_count require a condition such as {gte: 5}")
            for op, bound in condition_raw.items():
                if op == "field":
                    value_field = resolve_field(str(bound))
                    continue
                if op not in {"gt", "gte", "lt", "lte", "eq"}:
                    raise RuleError(f"unsupported correlation operator '{op}'")
                condition[op] = int(bound)
            if ctype == "value_count" and not value_field:
                raise RuleError("value_count requires condition.field")
        elif ctype == "temporal_ordered" and len(rules) < 2:
            raise RuleError("temporal_ordered requires at least two rules")
        return CorrelationRuleDef(
            meta=meta,
            type=ctype,
            rules=rules,
            group_by=group_by,
            timespan=_parse_timespan(corr.get("timespan")),
            condition=condition,
            value_field=value_field,
        )

    logsource = doc.get("logsource") or {}
    key = (logsource.get("product"), logsource.get("category"), logsource.get("service"))
    if key not in LOGSOURCE_MAP:
        raise RuleError(f"unsupported logsource {logsource}")
    category, actions = LOGSOURCE_MAP[key]

    detection = doc.get("detection")
    if not isinstance(detection, dict) or "condition" not in detection:
        raise RuleError("detection block with a condition is required")
    condition = detection["condition"]
    if isinstance(condition, list):
        if len(condition) != 1:
            raise RuleError("multiple conditions are not supported")
        condition = condition[0]
    used: set[str] = set()
    selections = {
        str(name): _selection_matcher(str(name), body, used)
        for name, body in detection.items()
        if name not in {"condition", "timeframe"}
    }
    if "timeframe" in detection:
        raise RuleError("'timeframe' is deprecated in Sigma; use a correlation rule")
    matcher = _ConditionParser(_tokenize(str(condition)), selections).parse()
    return DetectionRuleDef(
        meta=meta, category=category, actions=actions, matcher=matcher, used_fields=used
    )
