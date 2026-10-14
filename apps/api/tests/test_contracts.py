"""Contract tests: the committed JSON Schemas and OpenAPI document must match the code, and
example payloads shipped for agent developers must validate."""

from __future__ import annotations

import json

import jsonschema
import pytest

from aegis.events.contract import EventBatch, EventIn, HeartbeatIn, IngestResult
from aegis.main import create_app
from tests.conftest import ROOT, event

SCHEMAS = ROOT / "packages" / "event-schemas" / "schemas"


@pytest.mark.parametrize(
    ("name", "model"),
    [
        ("ace-event.v1.schema.json", EventIn),
        ("ace-batch.v1.schema.json", EventBatch),
        ("ace-heartbeat.v1.schema.json", HeartbeatIn),
        ("ace-ingest-result.v1.schema.json", IngestResult),
    ],
)
def test_committed_schema_matches_model(name: str, model: type) -> None:
    committed = json.loads((SCHEMAS / name).read_text())
    generated = model.model_json_schema()  # type: ignore[attr-defined]
    generated["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    assert committed == json.loads(json.dumps(generated)), (
        f"{name} is stale: run `aegis export-schemas`"
    )


def test_examples_validate_against_schema() -> None:
    schema = json.loads((SCHEMAS / "ace-event.v1.schema.json").read_text())
    examples = json.loads((ROOT / "packages" / "event-schemas" / "examples.json").read_text())
    assert examples
    for example in examples:
        jsonschema.validate(example, schema)
        EventIn.model_validate(example)


def test_generated_events_validate_against_schema() -> None:
    schema = json.loads((SCHEMAS / "ace-event.v1.schema.json").read_text())
    jsonschema.validate(event(), schema)


def test_openapi_document_is_current() -> None:
    committed = json.loads((ROOT / "packages" / "api-contracts" / "openapi.json").read_text())
    current = json.loads(json.dumps(create_app().openapi()))
    assert committed["paths"].keys() == current["paths"].keys(), (
        "openapi.json is stale: run `aegis export-openapi`"
    )
    assert committed["components"] == current["components"]
