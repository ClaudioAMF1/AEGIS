//! aegis-agent — Linux telemetry agent for AEGIS.
//!
//! Usage:
//!   aegis-agent run    --config /etc/aegis/agent.toml   collect and ship telemetry
//!   aegis-agent check  --config /etc/aegis/agent.toml   validate config, token and API reachability
//!   aegis-agent snapshot                                print one process/network snapshot (no network)
//!   aegis-agent sample                                  print a sample ACE batch (contract tests)

mod collectors;
mod config;
mod event;
mod procfs;
mod redact;
mod sender;
mod spool;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chrono::Utc;
use tokio::sync::mpsc;

use crate::collectors::Sink;
use crate::config::Config;
use crate::event::{EventFactory, Host};
use crate::procfs::ProcFs;

fn host(config: Option<&Config>, procfs: &ProcFs) -> Host {
    let hostname = config
        .and_then(|c| c.hostname.clone())
        .unwrap_or_else(|| procfs::hostname(procfs));
    Host {
        hostname,
        os: procfs::os_release(),
        ip: vec![],
    }
}

fn config_path(args: &[String]) -> Result<PathBuf> {
    match args.iter().position(|a| a == "--config") {
        Some(i) => Ok(PathBuf::from(
            args.get(i + 1).context("--config requires a path")?,
        )),
        None => Ok(PathBuf::from("/etc/aegis/agent.toml")),
    }
}

fn last_seq(config: &Config) -> u64 {
    std::fs::read_to_string(config.state_dir.join("state.json"))
        .ok()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
        .and_then(|v| v["last_seq"].as_u64())
        .unwrap_or(0)
}

async fn run(config: Config) -> Result<()> {
    let token = config.token()?;
    std::fs::create_dir_all(&config.state_dir)
        .with_context(|| format!("creating state dir {}", config.state_dir.display()))?;
    let procfs = ProcFs::new("/proc");
    let users = procfs::users(std::path::Path::new("/etc/passwd"));
    let factory = Arc::new(EventFactory::new(
        host(Some(&config), &procfs),
        last_seq(&config),
    ));
    let (tx, rx) = mpsc::channel(config.sender.queue_capacity);
    let sink = Sink::new(tx, config.sender.max_events_per_second);
    let redactor = || {
        redact::Redactor::new(
            &config.privacy.redact_patterns,
            config.privacy.collect_command_line,
        )
    };

    let mut start = factory.event("system", "agent_start", Utc::now());
    start
        .attributes
        .insert("agent.version".into(), sender::AGENT_VERSION.into());
    sink.emit(start);

    let c = &config.collectors;
    if c.process.enabled {
        let collector =
            collectors::process::ProcessCollector::new(procfs.clone(), users.clone(), redactor()?);
        tokio::spawn(collector.run(
            factory.clone(),
            sink.clone(),
            Duration::from_millis(c.process.poll_interval_ms),
        ));
    }
    if c.network.enabled {
        let collector = collectors::network::NetworkCollector::new(
            procfs.clone(),
            users.clone(),
            c.network.ignore_loopback,
        );
        tokio::spawn(collector.run(
            factory.clone(),
            sink.clone(),
            Duration::from_millis(c.network.poll_interval_ms),
        ));
    }
    if c.file.enabled {
        let (paths, f, s) = (c.file.paths.clone(), factory.clone(), sink.clone());
        std::thread::Builder::new()
            .name("aegis-inotify".into())
            .spawn(move || {
                if let Err(err) = collectors::file::run_blocking(paths, f, s) {
                    tracing::error!(%err, "file collector stopped");
                }
            })?;
    }
    if c.auth.enabled {
        tokio::spawn(collectors::auth::run(
            c.auth.log_files.clone(),
            factory.clone(),
            sink.clone(),
        ));
    }

    let spool = spool::Spool::open(
        &config.state_dir.join("spool"),
        config.sender.max_buffer_bytes,
    )?;
    let client = Arc::new(sender::Client::new(&config, token)?);
    tracing::info!(host = %factory.host().hostname, api = %config.api_url, "aegis-agent started");
    let delivery = tokio::spawn(sender::run(
        client,
        rx,
        spool,
        config.clone(),
        sink.clone(),
        factory.clone(),
    ));
    tokio::select! {
        _ = tokio::signal::ctrl_c() => tracing::info!("shutting down"),
        _ = delivery => tracing::warn!("delivery loop ended"),
    }
    Ok(())
}

async fn check(config: Config) -> Result<()> {
    config.token()?;
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(config.insecure_skip_tls_verify)
        .timeout(Duration::from_secs(5))
        .build()?;
    let health: serde_json::Value = client
        .get(format!(
            "{}/api/v1/health",
            config.api_url.trim_end_matches('/')
        ))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    println!("config ok; token file readable; api health: {health}");
    Ok(())
}

fn snapshot() -> Result<()> {
    let procfs = ProcFs::new("/proc");
    let factory = EventFactory::new(host(None, &procfs), 0);
    let users = procfs::users(std::path::Path::new("/etc/passwd"));
    let redactor = redact::Redactor::new(&config::Privacy::default().redact_patterns, true)?;
    let mut processes =
        collectors::process::ProcessCollector::new(procfs.clone(), users.clone(), redactor);
    let mut network = collectors::network::NetworkCollector::new(procfs, users, true);
    let mut events = processes.poll(&factory);
    events.extend(network.poll(&factory));
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({ "events": events }))?
    );
    Ok(())
}

fn sample() -> Result<()> {
    use crate::event::{Auth, File, Network, Process, User};
    let factory = EventFactory::new(
        Host {
            hostname: "lab-sample-01".into(),
            os: Some("Linux".into()),
            ip: vec!["10.20.0.99".into()],
        },
        0,
    );
    let now = Utc::now();
    let mut p = factory.event("process", "start", now);
    p.user = Some(User {
        name: "deploy".into(),
        uid: Some(1001),
    });
    p.process = Some(Process {
        pid: 4242,
        ppid: Some(1),
        name: "bash".into(),
        executable: Some("/usr/bin/bash".into()),
        command_line: Some("bash -c id".into()),
        parent_name: Some("sshd".into()),
        ..Process::default()
    });
    let mut n = factory.event("network", "connect", now);
    n.network = Some(Network {
        direction: "outbound",
        protocol: "tcp",
        src_ip: "10.20.0.99".into(),
        src_port: 50000,
        dst_ip: "198.51.100.23".into(),
        dst_port: 443,
        state: Some("established".into()),
    });
    let mut f = factory.event("file", "modify", now);
    f.file = Some(File {
        path: "/etc/cron.d/backup".into(),
        target_path: None,
        mode: Some("644".into()),
        size: Some(120),
    });
    let mut a = factory.event("authentication", "login_failure", now);
    a.auth = Some(Auth {
        method: "password".into(),
        outcome: "failure",
        source_ip: Some("203.0.113.45".into()),
        target_user: Some("root".into()),
        service: Some("sshd".into()),
    });
    let s = factory.event("system", "agent_start", now);
    println!(
        "{}",
        serde_json::to_string_pretty(
            &serde_json::json!({ "events": [p, n, f, a, s], "agent_version": sender::AGENT_VERSION })
        )?
    );
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .json()
        .with_writer(std::io::stderr)
        .init();
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("run") => run(Config::load(&config_path(&args)?)?).await,
        Some("check") => check(Config::load(&config_path(&args)?)?).await,
        Some("snapshot") => snapshot(),
        Some("sample") => sample(),
        _ => bail!("usage: aegis-agent <run|check|snapshot|sample> [--config PATH]"),
    }
}
