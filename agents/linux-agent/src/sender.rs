//! Delivery: batching, authenticated transport, retries with backoff, spooling and heartbeats.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use anyhow::Result;
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::mpsc;

use crate::collectors::Sink;
use crate::config::Config;
use crate::event::{Event, EventFactory};
use crate::spool::Spool;

pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Deserialize)]
struct Rejected {
    index: usize,
    reason: String,
}

#[derive(Debug, Deserialize)]
struct IngestResult {
    accepted: u64,
    duplicates: u64,
    rejected: Vec<Rejected>,
}

#[derive(Debug, Deserialize)]
struct PendingAction {
    id: String,
    action_type: String,
}

#[derive(Debug, Deserialize)]
struct HeartbeatOut {
    pending_actions: Vec<PendingAction>,
}

pub enum Delivery {
    Delivered,
    /// Transient failure: keep the batch and retry after the given delay.
    Retry(Duration),
    /// The server will never accept this batch (e.g. 413): drop it.
    Drop,
}

pub struct Client {
    http: reqwest::Client,
    base: String,
    token: String,
}

impl Client {
    pub fn new(config: &Config, token: String) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent(format!("aegis-agent/{AGENT_VERSION}"))
            .danger_accept_invalid_certs(config.insecure_skip_tls_verify)
            .build()?;
        Ok(Self {
            http,
            base: config.api_url.trim_end_matches('/').to_string(),
            token,
        })
    }

    pub async fn send(&self, events: &serde_json::Value, buffer_depth: u64) -> Delivery {
        let body =
            json!({"events": events, "agent_version": AGENT_VERSION, "buffer_depth": buffer_depth});
        let response = self
            .http
            .post(format!("{}/api/v1/ingest/events", self.base))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await;
        let response = match response {
            Ok(r) => r,
            Err(err) => {
                tracing::warn!(error = %err, "ingest request failed");
                return Delivery::Retry(Duration::from_secs(5));
            }
        };
        let status = response.status();
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_secs);
        match status {
            StatusCode::OK => {
                if let Ok(result) = response.json::<IngestResult>().await {
                    if !result.rejected.is_empty() {
                        // Rejected events are logged and dropped: retrying cannot fix them.
                        for r in result.rejected.iter().take(5) {
                            tracing::warn!(index = r.index, reason = %r.reason, "event rejected");
                        }
                    }
                    tracing::debug!(
                        accepted = result.accepted,
                        duplicates = result.duplicates,
                        "batch delivered"
                    );
                }
                Delivery::Delivered
            }
            StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE => {
                tracing::info!(%status, "server applying backpressure");
                Delivery::Retry(retry_after.unwrap_or(Duration::from_secs(10)))
            }
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                tracing::error!(%status, "agent token rejected (revoked?)");
                Delivery::Retry(Duration::from_secs(60))
            }
            StatusCode::PAYLOAD_TOO_LARGE
            | StatusCode::UNPROCESSABLE_ENTITY
            | StatusCode::BAD_REQUEST => {
                tracing::error!(%status, "batch refused by server; dropping");
                Delivery::Drop
            }
            _ => Delivery::Retry(retry_after.unwrap_or(Duration::from_secs(5))),
        }
    }

    async fn heartbeat(
        &self,
        factory: &EventFactory,
        depth: u64,
        dropped: u64,
        uptime: u64,
    ) -> Result<HeartbeatOut> {
        let body = json!({
            "agent_version": AGENT_VERSION,
            "host": factory.host(),
            "buffer_depth": depth,
            "dropped_events": dropped,
            "uptime_seconds": uptime,
        });
        let response = self
            .http
            .post(format!("{}/api/v1/ingest/heartbeat", self.base))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json().await?)
    }

    async fn ack_action(&self, id: &str, outcome: &str, detail: &str) -> Result<()> {
        self.http
            .post(format!("{}/api/v1/ingest/actions/{id}/result", self.base))
            .bearer_auth(&self.token)
            .json(&json!({"outcome": outcome, "detail": detail}))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

/// Main delivery loop: drains the spool first, then live events, never blocking collectors.
pub async fn run(
    client: Arc<Client>,
    mut rx: mpsc::Receiver<Event>,
    mut spool: Spool,
    config: Config,
    sink: Sink,
    factory: Arc<EventFactory>,
) {
    let flush = Duration::from_millis(config.sender.flush_interval_ms);
    let batch_size = config.sender.batch_size;
    let mut pending: Vec<Event> = Vec::with_capacity(batch_size);
    let mut last_flush = Instant::now();
    let mut backoff_until: Option<Instant> = None;
    let started = Instant::now();
    let mut heartbeat =
        tokio::time::interval(Duration::from_secs(config.sender.heartbeat_interval_s));
    let mut handled_actions: HashSet<String> = HashSet::new();
    let state_path = config.state_dir.join("state.json");

    loop {
        tokio::select! {
            maybe = rx.recv() => {
                match maybe {
                    Some(event) => pending.push(event),
                    None => break,
                }
            }
            _ = tokio::time::sleep(flush) => {}
            _ = heartbeat.tick() => {
                let dropped = sink.dropped.load(Ordering::Relaxed) + spool.dropped_events;
                match client.heartbeat(&factory, spool.depth(), dropped, started.elapsed().as_secs()).await {
                    Ok(out) => {
                        for action in out.pending_actions {
                            if !handled_actions.insert(action.id.clone()) {
                                continue;
                            }
                            // The bundled agent never alters host networking: isolation requests
                            // are acknowledged as simulated so the workflow can be exercised in labs.
                            let detail = format!("aegis-agent {AGENT_VERSION}: '{}' recorded; no firewall change (simulated)", action.action_type);
                            tracing::warn!(action = %action.action_type, id = %action.id, "response action received (simulated)");
                            if let Err(err) = client.ack_action(&action.id, "simulated", &detail).await {
                                tracing::warn!(%err, "could not acknowledge action");
                                handled_actions.remove(&action.id);
                            }
                        }
                    }
                    Err(err) => tracing::warn!(%err, "heartbeat failed"),
                }
                let _ = std::fs::write(&state_path, json!({"last_seq": factory.next_seq()}).to_string());
            }
        }

        let due =
            pending.len() >= batch_size || (!pending.is_empty() && last_flush.elapsed() >= flush);
        if backoff_until.is_some_and(|t| Instant::now() < t) {
            if pending.len() >= batch_size * 4 {
                // Offline for a while: move memory to the bounded spool.
                if let Err(err) = spool.push(&pending) {
                    tracing::error!(%err, "spool write failed");
                }
                pending.clear();
            }
            continue;
        }
        backoff_until = None;

        // Older spooled batches go first.
        while let Some((path, batch)) = spool.peek() {
            match client
                .send(&serde_json::Value::Array(batch), spool.depth())
                .await
            {
                Delivery::Delivered | Delivery::Drop => spool.ack(&path),
                Delivery::Retry(wait) => {
                    backoff_until = Some(Instant::now() + wait);
                    break;
                }
            }
        }
        if backoff_until.is_some() || !due {
            continue;
        }
        let batch: Vec<Event> = std::mem::take(&mut pending);
        last_flush = Instant::now();
        let payload = match serde_json::to_value(&batch) {
            Ok(v) => v,
            Err(err) => {
                tracing::error!(%err, "serialisation failed");
                continue;
            }
        };
        match client.send(&payload, spool.depth()).await {
            Delivery::Delivered | Delivery::Drop => {}
            Delivery::Retry(wait) => {
                backoff_until = Some(Instant::now() + wait);
                if let Err(err) = spool.push(&batch) {
                    tracing::error!(%err, "spool write failed; batch lost");
                }
            }
        }
    }
    // Shutdown: persist whatever is still in memory.
    if !pending.is_empty() {
        let _ = spool.push(&pending);
    }
    let _ = std::fs::write(
        &state_path,
        json!({"last_seq": factory.next_seq()}).to_string(),
    );
}
