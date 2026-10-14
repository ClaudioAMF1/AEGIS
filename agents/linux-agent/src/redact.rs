//! Command-line redaction: secrets passed as arguments never leave the host.

use regex::Regex;

pub struct Redactor {
    patterns: Vec<Regex>,
    enabled: bool,
}

impl Redactor {
    pub fn new(patterns: &[String], collect_command_line: bool) -> anyhow::Result<Self> {
        Ok(Self {
            patterns: patterns
                .iter()
                .map(|p| Regex::new(p))
                .collect::<Result<_, _>>()?,
            enabled: collect_command_line,
        })
    }

    pub fn command_line(&self, raw: &str) -> Option<String> {
        if !self.enabled || raw.is_empty() {
            return None;
        }
        let mut value = raw.to_string();
        for pattern in &self.patterns {
            value = pattern
                .replace_all(&value, |caps: &regex::Captures<'_>| match caps.get(1) {
                    Some(prefix) => format!("{}[redacted]", prefix.as_str()),
                    None => "://[redacted]@".to_string(),
                })
                .into_owned();
        }
        Some(crate::event::clip(&value, 4096))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Privacy;

    #[test]
    fn redacts_secrets() {
        let r = Redactor::new(&Privacy::default().redact_patterns, true).unwrap();
        let out = r.command_line("mysql --password=hunter2 -u root").unwrap();
        assert_eq!(out, "mysql --password=[redacted] -u root");
        let out = r
            .command_line("curl https://user:pa55@example.test/x")
            .unwrap();
        assert_eq!(out, "curl https://[redacted]@example.test/x");
        let out = r.command_line("tool --token abc123 run").unwrap();
        assert_eq!(out, "tool --token [redacted] run");
    }

    #[test]
    fn disabled_collects_nothing() {
        let r = Redactor::new(&[], false).unwrap();
        assert!(r.command_line("ls").is_none());
    }
}
