//! Minimal, dependency-free readers for /proc and /etc/passwd.
//!
//! The root directory is injectable so collectors can be unit-tested against a fake /proc tree.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub uid: Option<u32>,
    pub executable: Option<String>,
    pub cmdline: String,
    pub cwd: Option<String>,
    /// Start time in clock ticks since boot (field 22 of /proc/PID/stat): distinguishes PID reuse.
    pub start_ticks: u64,
}

#[derive(Clone)]
pub struct ProcFs {
    root: PathBuf,
}

impl ProcFs {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn pids(&self) -> Vec<u32> {
        let Ok(entries) = fs::read_dir(&self.root) else {
            return vec![];
        };
        entries
            .filter_map(|e| e.ok()?.file_name().to_str()?.parse::<u32>().ok())
            .collect()
    }

    pub fn process(&self, pid: u32) -> Option<ProcInfo> {
        let base = self.root.join(pid.to_string());
        let stat = fs::read_to_string(base.join("stat")).ok()?;
        let (name, rest) = parse_stat(&stat)?;
        let fields: Vec<&str> = rest.split_whitespace().collect();
        // rest starts at field 3 (state); ppid is field 4, starttime field 22.
        let ppid = fields.get(1)?.parse().ok()?;
        let start_ticks = fields.get(19)?.parse().ok()?;
        let cmdline = fs::read(base.join("cmdline"))
            .map(|raw| {
                raw.split(|b| *b == 0)
                    .filter(|part| !part.is_empty())
                    .map(|part| String::from_utf8_lossy(part).into_owned())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();
        let uid = fs::read_to_string(base.join("status"))
            .ok()
            .and_then(|status| {
                status
                    .lines()
                    .find(|l| l.starts_with("Uid:"))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|v| v.parse().ok())
            });
        let link = |entry: &str| {
            fs::read_link(base.join(entry)).ok().map(|p| {
                p.to_string_lossy()
                    .trim_end_matches(" (deleted)")
                    .to_string()
            })
        };
        Some(ProcInfo {
            pid,
            ppid,
            name,
            uid,
            executable: link("exe"),
            cmdline,
            cwd: link("cwd"),
            start_ticks,
        })
    }

    pub fn read(&self, relative: &str) -> Option<String> {
        fs::read_to_string(self.root.join(relative)).ok()
    }
}

/// Split `/proc/PID/stat` into (comm, remainder). `comm` may contain spaces and parentheses,
/// so it is delimited by the first '(' and the last ')'.
pub fn parse_stat(stat: &str) -> Option<(String, &str)> {
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    Some((stat[open + 1..close].to_string(), stat.get(close + 2..)?))
}

/// uid -> user name from an /etc/passwd style file.
pub fn users(passwd: &Path) -> HashMap<u32, String> {
    fs::read_to_string(passwd)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let mut parts = line.split(':');
            let name = parts.next()?;
            let uid = parts.nth(1)?.parse().ok()?;
            Some((uid, name.to_string()))
        })
        .collect()
}

pub fn hostname(procfs: &ProcFs) -> String {
    procfs
        .read("sys/kernel/hostname")
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "unknown-host".into())
}

pub fn os_release() -> Option<String> {
    let text = fs::read_to_string("/etc/os-release").ok()?;
    text.lines()
        .find_map(|l| l.strip_prefix("PRETTY_NAME="))
        .map(|v| v.trim_matches('"').to_string())
}

#[cfg(test)]
pub mod testing {
    use super::*;

    /// Build a fake /proc entry for tests.
    pub fn fake_process(root: &Path, pid: u32, ppid: u32, comm: &str, cmd: &[&str], start: u64) {
        let dir = root.join(pid.to_string());
        fs::create_dir_all(&dir).unwrap();
        let mut stat = format!("{pid} ({comm}) S {ppid}");
        // Fields 5..=22; starttime is field 22.
        for field in 5..=22 {
            stat.push_str(&format!(" {}", if field == 22 { start } else { 0 }));
        }
        fs::write(dir.join("stat"), stat).unwrap();
        fs::write(dir.join("cmdline"), cmd.join("\0")).unwrap();
        fs::write(
            dir.join("status"),
            "Name:\tx\nUid:\t1000\t1000\t1000\t1000\n",
        )
        .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::testing::fake_process;
    use super::*;

    #[test]
    fn parses_comm_with_spaces_and_parens() {
        let (name, rest) = parse_stat("42 (my (weird) proc) S 1 2 3").unwrap();
        assert_eq!(name, "my (weird) proc");
        assert_eq!(rest, "S 1 2 3");
    }

    #[test]
    fn reads_fake_process() {
        let dir = tempdir();
        fake_process(&dir, 100, 1, "bash", &["bash", "-c", "echo hi"], 777);
        let fs = ProcFs::new(&dir);
        let p = fs.process(100).unwrap();
        assert_eq!((p.pid, p.ppid, p.name.as_str()), (100, 1, "bash"));
        assert_eq!(p.cmdline, "bash -c echo hi");
        assert_eq!(p.uid, Some(1000));
        assert_eq!(p.start_ticks, 777);
        assert_eq!(fs.pids(), vec![100]);
    }

    #[test]
    fn parses_passwd() {
        let dir = tempdir();
        let path = dir.join("passwd");
        fs::write(
            &path,
            "root:x:0:0:root:/root:/bin/bash\ndeploy:x:1001:1001::/home/deploy:/bin/sh\n",
        )
        .unwrap();
        let users = users(&path);
        assert_eq!(users.get(&1001).map(String::as_str), Some("deploy"));
    }

    pub fn tempdir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("aegis-agent-test-{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}
