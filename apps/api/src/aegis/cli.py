"""Command-line administration: ``aegis <command>``."""

from __future__ import annotations

import argparse
import getpass
import json
import secrets
import sys
from pathlib import Path

from sqlalchemy import select

from aegis.config import get_settings
from aegis.db import session_factory


def _migrate(_: argparse.Namespace) -> int:
    from aegis.migrations import upgrade_head

    upgrade_head()
    _seed_roles()
    print("database is at the latest revision")
    return 0


def _seed_roles() -> None:
    from aegis.models import Role
    from aegis.security.rbac import ROLE_DESCRIPTIONS

    with session_factory()() as db:
        for name, description in ROLE_DESCRIPTIONS.items():
            if db.get(Role, name) is None:
                db.add(Role(name=name, description=description))
        db.commit()


def _create_user(args: argparse.Namespace) -> int:
    from aegis.models import RoleName, User
    from aegis.security.crypto import hash_password, password_problems

    _seed_roles()
    email = args.email.lower()
    generated = False
    if args.password_stdin:
        password = sys.stdin.readline().rstrip("\n")
    elif args.generate_password:
        password = secrets.token_urlsafe(18)
        generated = True
    else:
        password = getpass.getpass("Password: ")
        if password != getpass.getpass("Repeat password: "):
            print("passwords do not match", file=sys.stderr)
            return 1
    problems = password_problems(password, email)
    if problems:
        print("password " + "; ".join(problems), file=sys.stderr)
        return 1
    with session_factory()() as db:
        if db.scalar(select(User).where(User.email == email)):
            print(f"user {email} already exists", file=sys.stderr)
            return 1
        db.add(
            User(
                email=email,
                display_name=args.name or email.split("@")[0],
                role=RoleName(args.role).value,
                password_hash=hash_password(password),
            )
        )
        db.commit()
    print(f"created {args.role} {email}")
    if generated:
        # Printed once to the operator's terminal; never logged or stored in plain text.
        print(f"generated password: {password}")
    return 0


def _export_schemas(args: argparse.Namespace) -> int:
    from aegis.events.contract import EventBatch, EventIn, HeartbeatIn, IngestResult

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    schemas = {
        "ace-event.v1.schema.json": EventIn.model_json_schema(),
        "ace-batch.v1.schema.json": EventBatch.model_json_schema(),
        "ace-heartbeat.v1.schema.json": HeartbeatIn.model_json_schema(),
        "ace-ingest-result.v1.schema.json": IngestResult.model_json_schema(),
    }
    for name, schema in schemas.items():
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        (out / name).write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n")
    print(f"wrote {len(schemas)} schemas to {out}")
    return 0


def _export_openapi(args: argparse.Namespace) -> int:
    from aegis.main import create_app

    spec = create_app().openapi()
    Path(args.output).write_text(json.dumps(spec, indent=2, sort_keys=True) + "\n")
    print(f"wrote OpenAPI spec to {args.output}")
    return 0


def _retention(args: argparse.Namespace) -> int:
    from aegis.services.retention import purge

    with session_factory()() as db:
        result = purge(db, args.days)
    print(f"deleted {result['events']} events older than {result['retention_days']} days")
    return 0


def _demo(args: argparse.Namespace) -> int:
    from aegis.demo import runner
    from aegis.detection.registry import registry

    with session_factory()() as db:
        registry.bootstrap(db)
        if args.reset:
            print(json.dumps(runner.reset(db)))
        for scenario in args.scenario or []:
            simulation = runner.start(db, scenario, None)
            print(
                f"{scenario}: {simulation.status}, events={simulation.events_sent}, "
                f"alerts={simulation.alerts_created}"
            )
    return 0


def _rules(args: argparse.Namespace) -> int:
    from aegis.detection.registry import discover

    rules, errors = discover(args.dir or get_settings().rules_dir)
    for rule in rules:
        meta = rule.definition.meta
        print(f"ok   {meta.rule_id:<40} {meta.level:<13} {rule.path}")
    for error in errors:
        print(f"FAIL {error.path}: {error.error}")
    return 1 if errors else 0


def _worker(_: argparse.Namespace) -> int:
    from aegis.worker import run_forever

    run_forever()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aegis", description="AEGIS administration")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("migrate", help="apply database migrations").set_defaults(func=_migrate)

    user = sub.add_parser("create-user", help="create a user (e.g. the first administrator)")
    user.add_argument("--email", required=True)
    user.add_argument("--name")
    user.add_argument(
        "--role", choices=["administrator", "analyst", "viewer"], default="administrator"
    )
    source = user.add_mutually_exclusive_group()
    source.add_argument("--password-stdin", action="store_true")
    source.add_argument("--generate-password", action="store_true")
    user.set_defaults(func=_create_user)

    schemas = sub.add_parser("export-schemas", help="write ACE JSON Schemas")
    schemas.add_argument("--output", default="../../packages/event-schemas/schemas")
    schemas.set_defaults(func=_export_schemas)

    openapi = sub.add_parser("export-openapi", help="write the OpenAPI document")
    openapi.add_argument("--output", default="../../packages/api-contracts/openapi.json")
    openapi.set_defaults(func=_export_openapi)

    retention = sub.add_parser("retention", help="purge events beyond the retention window")
    retention.add_argument("--days", type=int)
    retention.set_defaults(func=_retention)

    demo = sub.add_parser("demo", help="load demo scenarios through the pipeline")
    demo.add_argument("scenario", nargs="*")
    demo.add_argument("--reset", action="store_true")
    demo.set_defaults(func=_demo)

    rules = sub.add_parser("rules", help="validate rule files")
    rules.add_argument("--dir")
    rules.set_defaults(func=_rules)

    sub.add_parser("worker", help="run the detection worker").set_defaults(func=_worker)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
