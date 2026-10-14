"""Synthetic scenario loader.

Scenarios are YAML files in ``simulations/scenarios``. They describe *what an endpoint would
report* (process starts, logins, connections, file changes) in lab hosts that do not exist.
Nothing is executed: the expander only produces ACE v1 events, deterministically for a
given seed, which are then sent through the real ingestion pipeline by a synthetic agent.

All addresses used for "external" actors belong to the documentation ranges reserved by
RFC 5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), so no real third party is named.
"""

from __future__ import annotations

import copy
import hashlib
import random
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

_DURATION = re.compile(r"(\d+(?:\.\d+)?)(ms|s|m|h)")


def parse_duration(value: str | int | float) -> timedelta:
    if isinstance(value, (int, float)):
        return timedelta(seconds=value)
    text = str(value).strip()
    parts = _DURATION.findall(text)
    if not parts or "".join(a + u for a, u in parts) != text:
        raise ValueError(f"invalid duration '{value}' (examples: 30s, 5m, 1m30s, 2h)")
    units = {"ms": "milliseconds", "s": "seconds", "m": "minutes", "h": "hours"}
    total = timedelta()
    for amount, unit in parts:
        total += timedelta(**{units[unit]: float(amount)})
    return total


@dataclass
class Scenario:
    id: str
    title: str
    description: str
    duration: timedelta
    hosts: dict[str, dict[str, Any]]
    steps: list[dict[str, Any]]
    expected: dict[str, Any]
    tags: list[str]
    path: str

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "duration_seconds": int(self.duration.total_seconds()),
            "hosts": [h["hostname"] for h in self.hosts.values()],
            "expected": self.expected,
            "tags": self.tags,
        }


def load_scenarios(directory: str | Path) -> dict[str, Scenario]:
    scenarios: dict[str, Scenario] = {}
    for path in sorted(Path(directory).glob("*.yml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        scenario = Scenario(
            id=doc["id"],
            title=doc["title"],
            description=doc.get("description", "").strip(),
            duration=parse_duration(doc.get("duration", "30m")),
            hosts=doc["hosts"],
            steps=doc["steps"],
            expected=doc.get("expected", {}),
            tags=doc.get("tags", []),
            path=path.name,
        )
        scenarios[scenario.id] = scenario
    return scenarios


class _Expander:
    def __init__(self, scenario: Scenario, start: datetime, seed: int) -> None:
        self.scenario = scenario
        self.start = start
        self.rng = random.Random(seed)  # noqa: S311 - deterministic synthetic data, not crypto
        self.next_pid = 2000 + self.rng.randint(0, 500)
        self.refs: dict[str, dict[str, Any]] = {}
        # Event ids must be unique across scenarios and across runs (different anchors), yet
        # reproducible for the same (scenario, anchor, seed): derive the stream from all three.
        digest = hashlib.sha256(f"{scenario.id}|{start.isoformat()}|{seed}".encode()).digest()
        self.uuid_rng = random.Random(int.from_bytes(digest[:8], "big"))  # noqa: S311

    def _uuid(self) -> str:
        return str(uuid.UUID(int=self.uuid_rng.getrandbits(128), version=4))

    def _render(self, value: Any, index: int) -> Any:
        if isinstance(value, str):

            def repl(match: re.Match[str]) -> str:
                expr = match.group(1)
                if expr == "i":
                    return str(index)
                if expr.startswith("cycle:"):
                    options = expr[6:].split("|")
                    return options[index % len(options)]
                if expr.startswith("choice:"):
                    return str(self.rng.choice(expr[7:].split("|")))
                if expr.startswith("int:"):
                    lo, hi = expr[4:].split("-")
                    return str(self.rng.randint(int(lo), int(hi)))
                if expr.startswith("hex:"):
                    return "".join(
                        self.rng.choice("0123456789abcdef") for _ in range(int(expr[4:]))
                    )
                raise ValueError(f"unknown template expression '{expr}'")

            rendered = re.sub(r"\{\{\s*([^}]+?)\s*\}\}", repl, value)
            if rendered.isdigit() and value.strip().startswith("{{int:"):
                return int(rendered)
            return rendered
        if isinstance(value, dict):
            return {k: self._render(v, index) for k, v in value.items()}
        if isinstance(value, list):
            return [self._render(v, index) for v in value]
        return value

    def expand(self) -> list[dict[str, Any]]:
        events: list[tuple[datetime, dict[str, Any]]] = []
        for step in self.scenario.steps:
            at = parse_duration(step.get("at", 0))
            repeat = step.get("repeat") or {}
            count = int(repeat.get("count", 1))
            every = parse_duration(repeat.get("every", "1s"))
            jitter = parse_duration(repeat.get("jitter", 0)) if repeat.get("jitter") else None
            for index in range(count):
                offset = at + every * index
                if jitter:
                    offset += timedelta(seconds=self.rng.uniform(0, jitter.total_seconds()))
                template = copy.deepcopy(step["event"])
                event = self._render(template, index)
                events.append((self.start + offset, self._finalize(event, step)))
        events.sort(key=lambda item: item[0])
        out = []
        for seq, (when, event) in enumerate(events, start=1):
            event["occurred_at"] = when.isoformat()
            event["seq"] = seq
            out.append(event)
        return out

    def _finalize(self, event: dict[str, Any], step: dict[str, Any]) -> dict[str, Any]:
        host_key = event.pop("host")
        host = self.scenario.hosts[host_key]
        event["host"] = {
            "hostname": host["hostname"],
            "os": host.get("os"),
            "ip": host.get("ip", []),
        }
        event["event_id"] = self._uuid()
        event["schema_version"] = "1.0"
        proc = event.get("process")
        if proc is not None:
            ref = proc.pop("ref", None)
            parent_ref = proc.pop("parent", None)
            if "pid" not in proc:
                existing = self.refs.get(f"{host_key}:{ref}") if ref else None
                if existing and event["category"] != "process":
                    proc["pid"] = existing["pid"]
                else:
                    self.next_pid += self.rng.randint(1, 37)
                    proc["pid"] = self.next_pid
            if parent_ref:
                parent = self.refs.get(f"{host_key}:{parent_ref}")
                if parent is None:
                    raise ValueError(f"step references unknown parent '{parent_ref}'")
                proc["ppid"] = parent["pid"]
                proc.setdefault("parent_name", parent["name"])
                if parent.get("executable"):
                    proc.setdefault("parent_executable", parent["executable"])
            if ref and event["category"] == "process":
                self.refs[f"{host_key}:{ref}"] = proc
        if event.get("network") and event["network"].get("src_ip") == "host":
            event["network"]["src_ip"] = host.get("ip", ["10.0.0.1"])[0]
        if event.get("network") and event["network"].get("dst_ip") == "host":
            event["network"]["dst_ip"] = host.get("ip", ["10.0.0.1"])[0]
        return event


def expand(scenario: Scenario, start: datetime, seed: int = 1337) -> list[dict[str, Any]]:
    return _Expander(scenario, start, seed).expand()
