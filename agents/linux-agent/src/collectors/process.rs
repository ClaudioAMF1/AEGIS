//! Process starts, discovered by diffing /proc snapshots.
//!
//! Polling misses processes that live shorter than the interval; this is a documented
//! limitation of the procfs source (an eBPF exec tracepoint is the planned upgrade). Parent
//! names are resolved from the snapshot, so short-lived parents may be reported by the API's
//! enrichment instead.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use chrono::Utc;

use crate::collectors::Sink;
use crate::event::{EventFactory, Process, User, clip};
use crate::procfs::{ProcFs, ProcInfo};
use crate::redact::Redactor;

pub struct ProcessCollector {
    pub procfs: ProcFs,
    pub users: HashMap<u32, String>,
    pub redactor: Redactor,
    /// (pid, start_ticks) of processes already reported.
    known: HashSet<(u32, u64)>,
    self_pid: u32,
}

impl ProcessCollector {
    pub fn new(procfs: ProcFs, users: HashMap<u32, String>, redactor: Redactor) -> Self {
        Self {
            procfs,
            users,
            redactor,
            known: HashSet::new(),
            self_pid: std::process::id(),
        }
    }

    /// Record the current process table without emitting events (agent start-up).
    pub fn prime(&mut self) {
        for (key, _) in self.snapshot() {
            self.known.insert(key);
        }
    }

    fn snapshot(&self) -> Vec<((u32, u64), ProcInfo)> {
        self.procfs
            .pids()
            .into_iter()
            .filter_map(|pid| self.procfs.process(pid))
            .map(|p| ((p.pid, p.start_ticks), p))
            .collect()
    }

    /// One polling step: returns newly started processes as events.
    pub fn poll(&mut self, factory: &EventFactory) -> Vec<crate::event::Event> {
        let snapshot = self.snapshot();
        let by_pid: HashMap<u32, &ProcInfo> = snapshot.iter().map(|(_, p)| (p.pid, p)).collect();
        let current: HashSet<(u32, u64)> = snapshot.iter().map(|(k, _)| *k).collect();
        let mut events = Vec::new();
        let mut fresh: Vec<&ProcInfo> = snapshot
            .iter()
            .filter(|(key, p)| !self.known.contains(key) && p.pid != self.self_pid)
            .map(|(_, p)| p)
            .collect();
        fresh.sort_by_key(|p| p.start_ticks);
        for info in fresh {
            // Kernel threads have no cmdline and no executable: skip them.
            if info.cmdline.is_empty() && info.executable.is_none() {
                continue;
            }
            let parent = by_pid.get(&info.ppid);
            let mut event = factory.event("process", "start", Utc::now());
            event.user = info.uid.map(|uid| User {
                name: self
                    .users
                    .get(&uid)
                    .cloned()
                    .unwrap_or_else(|| uid.to_string()),
                uid: Some(uid),
            });
            event.process = Some(Process {
                pid: info.pid,
                ppid: Some(info.ppid),
                name: clip(&info.name, 255),
                executable: info.executable.as_deref().map(|e| clip(e, 1024)),
                command_line: self.redactor.command_line(&info.cmdline),
                parent_name: parent.map(|p| clip(&p.name, 255)),
                parent_executable: parent
                    .and_then(|p| p.executable.as_deref().map(|e| clip(e, 1024))),
                working_directory: info.cwd.as_deref().map(|c| clip(c, 1024)),
            });
            events.push(event);
        }
        self.known = current;
        events
    }

    pub async fn run(
        mut self,
        factory: std::sync::Arc<EventFactory>,
        sink: Sink,
        interval: Duration,
    ) {
        self.prime();
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            for event in self.poll(&factory) {
                sink.emit(event);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Host;
    use crate::procfs::testing::fake_process;

    #[test]
    fn reports_only_new_processes_with_parent() {
        let dir = std::env::temp_dir().join(format!("aegis-proc-{}", uuid::Uuid::now_v7()));
        fake_process(&dir, 1, 0, "init", &["/sbin/init"], 1);
        let mut collector = ProcessCollector::new(
            ProcFs::new(&dir),
            HashMap::from([(1000, "deploy".to_string())]),
            Redactor::new(&crate::config::Privacy::default().redact_patterns, true).unwrap(),
        );
        let factory = EventFactory::new(
            Host {
                hostname: "h".into(),
                os: None,
                ip: vec![],
            },
            0,
        );
        collector.prime();
        assert!(collector.poll(&factory).is_empty());
        fake_process(
            &dir,
            50,
            1,
            "bash",
            &["bash", "-c", "mysql --password=x"],
            10,
        );
        let events = collector.poll(&factory);
        assert_eq!(events.len(), 1);
        let p = events[0].process.as_ref().unwrap();
        assert_eq!(p.parent_name.as_deref(), Some("init"));
        assert_eq!(
            p.command_line.as_deref(),
            Some("bash -c mysql --password=[redacted]")
        );
        assert_eq!(events[0].user.as_ref().unwrap().name, "deploy");
        // PID reuse with a new start time is a new process.
        fake_process(&dir, 50, 1, "sleep", &["sleep", "5"], 99);
        assert_eq!(collector.poll(&factory).len(), 1);
        assert!(collector.poll(&factory).is_empty());
    }
}
