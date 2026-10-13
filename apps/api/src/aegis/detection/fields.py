"""Field model used by detection rules.

Rules see an event as a flat mapping of dotted field names (``process.command_line``) to
scalar values. Sigma's Sysmon-style field names are translated through ``SIGMA_FIELD_MAP`` so
that a selected subset of upstream Linux Sigma rules can run unchanged.
"""

from __future__ import annotations

from typing import Any

# Sigma field name -> AEGIS Common Event field. Only fields we can actually populate on Linux
# are listed: an unmapped field makes the rule fail to load instead of silently never matching.
SIGMA_FIELD_MAP: dict[str, str] = {
    "Image": "process.executable",
    "CommandLine": "process.command_line",
    "ParentImage": "process.parent_executable",
    "ParentName": "process.parent_name",
    "CurrentDirectory": "process.working_directory",
    "ProcessId": "process.pid",
    "ParentProcessId": "process.ppid",
    "User": "user.name",
    "LogonId": "user.uid",
    "sha256": "process.hash_sha256",
    "DestinationIp": "network.dst_ip",
    "DestinationPort": "network.dst_port",
    "SourceIp": "network.src_ip",
    "SourcePort": "network.src_port",
    "Protocol": "network.protocol",
    "Initiated": "network.initiated",
    "TargetFilename": "file.path",
    "Computer": "host.hostname",
}

# Sigma logsource -> (category, set of actions) in the AEGIS event model.
LOGSOURCE_MAP: dict[tuple[str | None, str | None, str | None], tuple[str, frozenset[str]]] = {
    ("linux", "process_creation", None): ("process", frozenset({"start"})),
    ("linux", "network_connection", None): ("network", frozenset({"connect", "accept"})),
    ("linux", "file_event", None): ("file", frozenset({"create", "modify", "rename"})),
    ("linux", "file_create", None): ("file", frozenset({"create"})),
    ("linux", "file_change", None): ("file", frozenset({"modify", "chmod"})),
    ("linux", "file_delete", None): ("file", frozenset({"delete"})),
    ("linux", None, "auth"): ("authentication", frozenset({"login_success", "login_failure"})),
    ("linux", "authentication", None): (
        "authentication",
        frozenset({"login_success", "login_failure", "privilege_escalation"}),
    ),
    ("aegis", "authentication", None): (
        "authentication",
        frozenset({"login_success", "login_failure", "privilege_escalation", "logout"}),
    ),
    ("aegis", "process", None): ("process", frozenset({"start", "exit"})),
    ("aegis", "network", None): ("network", frozenset({"connect", "listen", "accept"})),
    ("aegis", "file", None): ("file", frozenset({"create", "modify", "delete", "rename", "chmod"})),
    ("aegis", "system", None): (
        "system",
        frozenset({"agent_start", "agent_stop", "service_start", "service_stop", "module_load"}),
    ),
}

NATIVE_PREFIXES = (
    "host.",
    "user.",
    "process.",
    "network.",
    "file.",
    "auth.",
    "attributes.",
    "intel.",
)
NATIVE_FIELDS = {"category", "action", "event_id", "occurred_at"}


def resolve_field(name: str) -> str:
    """Translate a rule field name into an event field, raising for unknown names."""
    if name in SIGMA_FIELD_MAP:
        return SIGMA_FIELD_MAP[name]
    if name in NATIVE_FIELDS or name.startswith(NATIVE_PREFIXES):
        return name
    raise ValueError(f"unsupported field '{name}'")


def flatten(payload: dict[str, Any], enrichment: dict[str, Any] | None = None) -> dict[str, Any]:
    """Flatten an ACE payload (``EventIn.model_dump(mode='json')``) into dotted fields."""
    flat: dict[str, Any] = {
        "event_id": payload.get("event_id"),
        "occurred_at": payload.get("occurred_at"),
        "category": payload.get("category"),
        "action": payload.get("action"),
    }
    for section in ("host", "user", "process", "network", "file", "auth"):
        value = payload.get(section)
        if isinstance(value, dict):
            for key, item in value.items():
                flat[f"{section}.{key}"] = item
    for key, item in (payload.get("attributes") or {}).items():
        flat[f"attributes.{key}"] = item
    network = payload.get("network")
    if isinstance(network, dict):
        flat["network.initiated"] = "true" if network.get("direction") == "outbound" else "false"
    for key, item in (enrichment or {}).items():
        if not isinstance(item, (dict, list)):
            flat[f"intel.{key}" if not key.startswith("intel.") else key] = item
    return flat
