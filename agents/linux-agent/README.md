# aegis-agent — Linux telemetry agent

Rust agent that collects security telemetry from a Linux host and ships it to the AEGIS API as
[ACE v1](../../packages/event-schemas/README.md) events.

> Install it **only** on machines you own or are explicitly authorised to monitor.

## What it collects

| Collector | Source | Events | Notes |
|---|---|---|---|
| process | `/proc` snapshots (default every 250 ms) | `process.start` | pid, ppid, name, executable, command line (redacted), cwd, uid→user, parent name |
| network | `/proc/net/tcp`, `/proc/net/tcp6` (every 1 s) | `network.connect` / `network.accept` | addresses, ports, owning process; loopback ignored by default |
| file | inotify on configured directories | `file.create/modify/delete/chmod` | path, mode, size — **never file contents** |
| auth | `auth.log` / `secure` (followed, rotation-aware) | `authentication.login_success/login_failure/privilege_escalation` | sshd and sudo lines |
| system | agent lifecycle | `system.agent_start` | agent version |

Not collected: packet payloads, file contents, environment variables, keystrokes, screen data.

## Privacy and safety

* Command lines pass through redaction before leaving the host (`--password=…`, bearer tokens,
  credentials in URLs by default; configurable regexes) and can be disabled entirely with
  `privacy.collect_command_line = false`.
* The agent is **read-only** on the host. Response actions delivered by the API (lab host
  isolation) are acknowledged as `simulated`: the bundled agent never changes firewall rules.
* Plain `http://` API URLs are refused unless the host is local/lab (`localhost`, RFC 1918
  `10.*`/`192.168.*`, `*.local`, `*.lab`).

## Reliability

* Events carry a UUIDv7 `event_id` and a per-agent `seq`; the API deduplicates by id, so
  retries are always safe.
* Batches that cannot be delivered (network error, 5xx, 429/503 backpressure honouring
  `Retry-After`) are written to a bounded on-disk spool (`state_dir/spool`, default 64 MiB) and
  delivered oldest-first when the API is reachable again. When the spool is full the oldest
  batches are discarded and counted.
* Collectors push into a bounded queue with a token-bucket rate limit
  (`max_events_per_second`); excess events are dropped and reported in heartbeats rather than
  blocking the host.
* Heartbeats (default 30 s) report version, spool depth, dropped events and uptime.

## Measured footprint

Release build on the development container (≈120 processes), default configuration, 30 s
sample: **~10 MB RSS, ~1.8 % of one CPU core**, 6 threads. Process polling dominates CPU; raise
`collectors.process.poll_interval_ms` to trade latency for lower usage.

## Usage

```bash
cargo build --release
sudo install -m 0755 target/release/aegis-agent /usr/local/bin/
sudo install -d -m 0700 /etc/aegis /var/lib/aegis-agent
sudo install -m 0600 packaging/agent.example.toml /etc/aegis/agent.toml   # edit api_url
# token from the console (endpoints → cadastrar agente) — shown once, stored as a hash server-side
sudo sh -c 'umask 077; cat > /etc/aegis/agent.token'
sudo aegis-agent check --config /etc/aegis/agent.toml
sudo install -m 0644 packaging/aegis-agent.service /etc/systemd/system/
sudo systemctl enable --now aegis-agent
```

Other commands:

* `aegis-agent snapshot` — print one process/network snapshot as ACE JSON (no network I/O).
* `aegis-agent sample` — print a sample batch; used by the cross-language contract test.

## Limitations (honest list)

* **Polling, not tracing**: processes that live shorter than the poll interval can be missed,
  and parent names of very short-lived parents may be unknown (the API fills them from earlier
  telemetry when possible). An eBPF `sched_process_exec` collector is the planned upgrade
  (see the project roadmap); it was deliberately postponed until the pipeline was validated.
* Network collection covers TCP only (no UDP/DNS yet); connections shorter than the poll
  interval can be missed.
* inotify watches are not recursive; list each directory explicitly.
* journald-only systems (no `auth.log`/`secure`) are not yet supported by the auth collector.
* Must run as root to read every process's `exe`, `cwd` and file descriptors.

## Tests

```bash
cargo test          # unit tests with a fake /proc tree, parsers, spool, redaction, config
cargo clippy --all-targets -- -D warnings
```

The API test suite validates `aegis-agent sample` against the committed JSON Schema when
`AEGIS_AGENT_BIN` points at a built binary (CI does this).
