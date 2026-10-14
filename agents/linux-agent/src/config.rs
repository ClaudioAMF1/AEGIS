//! Agent configuration (TOML). Every collector can be disabled; defaults favour low impact.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Base URL of the AEGIS API, e.g. `https://aegis.lab.local`.
    pub api_url: String,
    /// File containing the agent token (mode 0600). The token is never logged.
    pub token_file: PathBuf,
    /// Override the reported hostname (defaults to /proc/sys/kernel/hostname).
    pub hostname: Option<String>,
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    #[serde(default)]
    pub sender: SenderConfig,
    #[serde(default)]
    pub collectors: Collectors,
    #[serde(default)]
    pub privacy: Privacy,
    /// Accept self-signed certificates (lab only). Never enable in production.
    #[serde(default)]
    pub insecure_skip_tls_verify: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SenderConfig {
    pub batch_size: usize,
    pub flush_interval_ms: u64,
    pub heartbeat_interval_s: u64,
    /// Upper bound of the on-disk spool used while the API is unreachable.
    pub max_buffer_bytes: u64,
    /// Events per second accepted from collectors; excess is dropped and counted.
    pub max_events_per_second: u32,
    /// Bounded in-memory queue between collectors and the sender.
    pub queue_capacity: usize,
}

impl Default for SenderConfig {
    fn default() -> Self {
        Self {
            batch_size: 200,
            flush_interval_ms: 2000,
            heartbeat_interval_s: 30,
            max_buffer_bytes: 64 * 1024 * 1024,
            max_events_per_second: 500,
            queue_capacity: 10_000,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Collectors {
    pub process: ProcessCollector,
    pub network: NetworkCollector,
    pub file: FileCollector,
    pub auth: AuthCollector,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ProcessCollector {
    pub enabled: bool,
    pub poll_interval_ms: u64,
    /// Hash executables (SHA-256) up to this size; 0 disables hashing.
    pub hash_max_bytes: u64,
}

impl Default for ProcessCollector {
    fn default() -> Self {
        Self {
            enabled: true,
            poll_interval_ms: 250,
            hash_max_bytes: 0,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct NetworkCollector {
    pub enabled: bool,
    pub poll_interval_ms: u64,
    /// Skip loopback connections.
    pub ignore_loopback: bool,
}

impl Default for NetworkCollector {
    fn default() -> Self {
        Self {
            enabled: true,
            poll_interval_ms: 1000,
            ignore_loopback: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FileCollector {
    pub enabled: bool,
    /// Directories watched (non-recursive). Only metadata is collected, never content.
    pub paths: Vec<PathBuf>,
}

impl Default for FileCollector {
    fn default() -> Self {
        Self {
            enabled: true,
            paths: vec![
                "/etc".into(),
                "/etc/cron.d".into(),
                "/etc/sudoers.d".into(),
                "/var/spool/cron/crontabs".into(),
                "/root/.ssh".into(),
            ],
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AuthCollector {
    pub enabled: bool,
    /// Candidate log files; the first one that exists is followed.
    pub log_files: Vec<PathBuf>,
}

impl Default for AuthCollector {
    fn default() -> Self {
        Self {
            enabled: true,
            log_files: vec!["/var/log/auth.log".into(), "/var/log/secure".into()],
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Privacy {
    pub collect_command_line: bool,
    /// Regular expressions whose matches are replaced by `[redacted]` in command lines.
    pub redact_patterns: Vec<String>,
}

impl Default for Privacy {
    fn default() -> Self {
        Self {
            collect_command_line: true,
            redact_patterns: vec![
                r"(?i)(--?(password|passwd|pass|token|secret|api[-_]?key)[= ])\S+".into(),
                r"(?i)(authorization:\s*bearer\s+)\S+".into(),
                r"://[^/\s:@]+:[^/\s@]+@".into(),
            ],
        }
    }
}

fn default_state_dir() -> PathBuf {
    "/var/lib/aegis-agent".into()
}

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let config: Config = toml::from_str(&raw).context("parsing config")?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if !(self.api_url.starts_with("https://") || self.api_url.starts_with("http://")) {
            bail!("api_url must be an http(s) URL");
        }
        if self.api_url.starts_with("http://") && !is_local(&self.api_url) {
            bail!("plain http is only allowed for localhost / lab addresses; use https");
        }
        if self.sender.batch_size == 0 || self.sender.batch_size > 500 {
            bail!("sender.batch_size must be 1..=500 (API limit)");
        }
        for pattern in &self.privacy.redact_patterns {
            regex::Regex::new(pattern)
                .with_context(|| format!("invalid redact pattern {pattern}"))?;
        }
        Ok(())
    }

    pub fn token(&self) -> Result<String> {
        let token = std::fs::read_to_string(&self.token_file)
            .with_context(|| format!("reading token file {}", self.token_file.display()))?;
        let token = token.trim().to_string();
        if token.len() < 20 {
            bail!("token file does not contain a valid agent token");
        }
        Ok(token)
    }
}

fn is_local(url: &str) -> bool {
    let host = url
        .trim_start_matches("http://")
        .split(['/', ':'])
        .next()
        .unwrap_or("");
    host == "localhost"
        || host.starts_with("127.")
        || host.starts_with("10.")
        || host.starts_with("192.168.")
        || host.ends_with(".local")
        || host.ends_with(".lab")
        || host == "api"
        || host == "gateway"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Config {
        toml::from_str("api_url = \"https://aegis.example\"\ntoken_file = \"/tmp/t\"").unwrap()
    }

    #[test]
    fn defaults_are_valid() {
        base().validate().unwrap();
    }

    #[test]
    fn rejects_plain_http_to_public_hosts() {
        let mut c = base();
        c.api_url = "http://aegis.example.com".into();
        assert!(c.validate().is_err());
        c.api_url = "http://localhost:8000".into();
        c.validate().unwrap();
    }

    #[test]
    fn example_config_is_valid() {
        let example: Config = toml::from_str(include_str!("../packaging/agent.example.toml")).unwrap();
        example.validate().unwrap();
        assert_eq!(example.sender.batch_size, 200);
    }

    #[test]
    fn rejects_unknown_keys() {
        let parsed: Result<Config, _> =
            toml::from_str("api_url = \"https://a\"\ntoken_file = \"/t\"\nsurprise = 1");
        assert!(parsed.is_err());
    }
}
