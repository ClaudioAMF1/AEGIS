# AEGIS Common Event (ACE) v1 — schemas

Machine-readable contract for telemetry sent to `POST /api/v1/ingest/events`.

| File | Purpose |
| --- | --- |
| `schemas/ace-event.v1.schema.json` | One event |
| `schemas/ace-batch.v1.schema.json` | Request body (`{"events": [...]}`, 1–500 events) |
| `schemas/ace-heartbeat.v1.schema.json` | Agent heartbeat body |
| `schemas/ace-ingest-result.v1.schema.json` | Ingestion response |
| `examples.json` | One valid example per category |

The schemas are **generated** from the Pydantic models in
`apps/api/src/aegis/events/contract.py` (`aegis export-schemas`). The contract tests fail when
the committed files drift from the code, and the Rust agent serialises against the same
shape (its own contract test validates an agent-produced batch against these files).

Key rules:

* `event_id` is produced by the sender (UUID; v7 recommended) and is the idempotency key —
  re-sending an event is safe and is reported as a duplicate.
* `occurred_at` must include a timezone. Events more than 10 minutes in the future or older
  than 7 days (configurable) are rejected individually.
* `category` determines the allowed `action` values and the required section (`process`,
  `network`, `file`, `auth`).
* Unknown fields are rejected (`additionalProperties: false`) so typos never pass silently.
* No payload content is part of the contract: never file contents, never packet data.
