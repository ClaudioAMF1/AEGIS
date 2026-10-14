//! AEGIS Common Event (ACE) v1 — serialisation mirrors
//! `packages/event-schemas/schemas/ace-event.v1.schema.json`.

use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub struct Host {
    pub hostname: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    pub ip: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct User {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Process {
    pub pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_executable: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Network {
    pub direction: &'static str,
    pub protocol: &'static str,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct File {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Auth {
    pub method: String,
    pub outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub schema_version: &'static str,
    pub event_id: Uuid,
    pub occurred_at: String,
    pub seq: u64,
    pub category: &'static str,
    pub action: &'static str,
    pub host: Host,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<User>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<Process>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<Network>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<File>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<Auth>,
    #[serde(skip_serializing_if = "serde_json::Map::is_empty")]
    pub attributes: serde_json::Map<String, serde_json::Value>,
}

/// Builds events with stable identifiers (UUIDv7) and a per-agent monotonic sequence.
pub struct EventFactory {
    host: Host,
    seq: AtomicU64,
}

impl EventFactory {
    pub fn new(host: Host, start_seq: u64) -> Self {
        Self { host, seq: AtomicU64::new(start_seq) }
    }

    pub fn host(&self) -> &Host {
        &self.host
    }

    pub fn next_seq(&self) -> u64 {
        self.seq.load(Ordering::Relaxed)
    }

    pub fn event(&self, category: &'static str, action: &'static str, at: DateTime<Utc>) -> Event {
        Event {
            schema_version: "1.0",
            event_id: Uuid::now_v7(),
            occurred_at: at.to_rfc3339_opts(SecondsFormat::Micros, true),
            seq: self.seq.fetch_add(1, Ordering::Relaxed) + 1,
            category,
            action,
            host: self.host.clone(),
            user: None,
            process: None,
            network: None,
            file: None,
            auth: None,
            attributes: serde_json::Map::new(),
        }
    }
}

/// Truncate a string to at most `max` bytes on a char boundary (schema limits).
pub fn clip(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_string();
    }
    let mut end = max;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_is_monotonic_and_ids_unique() {
        let f = EventFactory::new(Host { hostname: "h".into(), os: None, ip: vec![] }, 10);
        let a = f.event("system", "agent_start", Utc::now());
        let b = f.event("system", "agent_start", Utc::now());
        assert_eq!((a.seq, b.seq), (11, 12));
        assert_ne!(a.event_id, b.event_id);
        assert!(a.occurred_at.ends_with('Z'));
    }

    #[test]
    fn clip_respects_utf8() {
        assert_eq!(clip("ação", 2), "a");
        assert_eq!(clip("abc", 10), "abc");
    }
}
