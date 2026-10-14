//! sshd / sudo authentication from auth.log (Debian/Ubuntu) or secure (RHEL family).
//! The file is followed from its end; rotation is detected by inode/size changes.

use std::fs::File as FsFile;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use chrono::Utc;
use regex::Regex;

use crate::collectors::Sink;
use crate::event::{Auth, Event, EventFactory, User, clip};

fn patterns() -> &'static [(Regex, &'static str, &'static str)] {
    static PATTERNS: OnceLock<Vec<(Regex, &'static str, &'static str)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            (Regex::new(r"sshd\[\d+\]: Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)").unwrap(), "login_success", "success"),
            (Regex::new(r"sshd\[\d+\]: Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)").unwrap(), "login_failure", "failure"),
            (Regex::new(r"sshd\[\d+\]: Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)").unwrap(), "login_failure", "failure"),
            (Regex::new(r"sudo:\s+(?P<user>\S+) : .*COMMAND=").unwrap(), "privilege_escalation", "success"),
        ]
    })
}

/// Parse one log line into an event (None when the line is not relevant).
pub fn parse_line(line: &str, factory: &EventFactory) -> Option<Event> {
    for (regex, action, outcome) in patterns() {
        let Some(caps) = regex.captures(line) else {
            continue;
        };
        let user = clip(caps.name("user")?.as_str(), 128);
        let ip = caps
            .name("ip")
            .and_then(|m| m.as_str().parse::<std::net::IpAddr>().ok());
        let method = caps.name("method").map(|m| m.as_str()).unwrap_or("sudo");
        let service = if *action == "privilege_escalation" {
            "sudo"
        } else {
            "sshd"
        };
        let mut event = factory.event("authentication", action, Utc::now());
        event.user = Some(User {
            name: user.clone(),
            uid: None,
        });
        event.auth = Some(Auth {
            method: clip(method, 32),
            outcome,
            source_ip: ip.map(|i| i.to_string()),
            target_user: Some(user),
            service: Some(service.into()),
        });
        return Some(event);
    }
    None
}

pub async fn run(candidates: Vec<PathBuf>, factory: std::sync::Arc<EventFactory>, sink: Sink) {
    let Some(path) = candidates.into_iter().find(|p| p.exists()) else {
        tracing::warn!(
            "auth collector: no auth log found (journald-only systems are not supported yet)"
        );
        return;
    };
    let mut position = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    let mut inode = std::fs::metadata(&path).map(|m| m.ino()).unwrap_or(0);
    let mut ticker = tokio::time::interval(Duration::from_millis(500));
    loop {
        ticker.tick().await;
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        if meta.ino() != inode || meta.len() < position {
            inode = meta.ino();
            position = 0; // rotated or truncated
        }
        if meta.len() == position {
            continue;
        }
        let Ok(mut file) = FsFile::open(&path) else {
            continue;
        };
        if file.seek(SeekFrom::Start(position)).is_err() {
            continue;
        }
        let mut reader = BufReader::new(file);
        let mut line = String::new();
        while reader.read_line(&mut line).map(|n| n > 0).unwrap_or(false) {
            if line.ends_with('\n') {
                position += line.len() as u64;
                if let Some(event) = parse_line(line.trim_end(), &factory) {
                    sink.emit(event);
                }
                line.clear();
            } else {
                break; // partial line: re-read on the next tick
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Host;

    fn factory() -> EventFactory {
        EventFactory::new(
            Host {
                hostname: "h".into(),
                os: None,
                ip: vec![],
            },
            0,
        )
    }

    #[test]
    fn parses_sshd_lines() {
        let f = factory();
        let ok = parse_line("Oct 13 21:04:05 web sshd[123]: Accepted publickey for deploy from 10.20.0.5 port 50422 ssh2", &f).unwrap();
        assert_eq!(ok.action, "login_success");
        let auth = ok.auth.unwrap();
        assert_eq!(
            (auth.method.as_str(), auth.source_ip.as_deref()),
            ("publickey", Some("10.20.0.5"))
        );
        let fail = parse_line(
            "sshd[9]: Failed password for invalid user oracle from 203.0.113.45 port 4 ssh2",
            &f,
        )
        .unwrap();
        assert_eq!(fail.action, "login_failure");
        assert_eq!(fail.auth.unwrap().target_user.as_deref(), Some("oracle"));
        let sudo = parse_line(
            "sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/id",
            &f,
        )
        .unwrap();
        assert_eq!(sudo.action, "privilege_escalation");
        assert!(parse_line("CRON[1]: pam_unix(cron:session): session opened", &f).is_none());
    }
}
