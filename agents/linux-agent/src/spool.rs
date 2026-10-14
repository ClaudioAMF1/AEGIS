//! Bounded on-disk spool for batches that could not be delivered. Each batch is one JSON file
//! written atomically (temp + rename). When the total size exceeds the limit the oldest batches
//! are discarded and counted — the agent never fills the disk.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::event::Event;

pub struct Spool {
    dir: PathBuf,
    max_bytes: u64,
    pub dropped_events: u64,
}

impl Spool {
    pub fn open(dir: &Path, max_bytes: u64) -> Result<Self> {
        fs::create_dir_all(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            max_bytes,
            dropped_events: 0,
        })
    }

    fn files(&self) -> Vec<PathBuf> {
        let mut files: Vec<PathBuf> = fs::read_dir(&self.dir)
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.path())
                    .filter(|p| p.extension().is_some_and(|e| e == "json"))
                    .collect()
            })
            .unwrap_or_default();
        files.sort();
        files
    }

    pub fn push(&mut self, events: &[Event]) -> Result<()> {
        let name = format!("{}.json", uuid::Uuid::now_v7());
        let tmp = self.dir.join(format!(".{name}.tmp"));
        fs::write(&tmp, serde_json::to_vec(events)?)?;
        fs::rename(&tmp, self.dir.join(name))?;
        self.enforce_limit();
        Ok(())
    }

    fn enforce_limit(&mut self) {
        let mut files = self.files();
        let mut total: u64 = files
            .iter()
            .filter_map(|f| fs::metadata(f).ok())
            .map(|m| m.len())
            .sum();
        while total > self.max_bytes && !files.is_empty() {
            let oldest = files.remove(0);
            let size = fs::metadata(&oldest).map(|m| m.len()).unwrap_or(0);
            if let Ok(raw) = fs::read(&oldest) {
                let count = serde_json::from_slice::<Vec<serde_json::Value>>(&raw)
                    .map(|v| v.len())
                    .unwrap_or(0);
                self.dropped_events += count as u64;
            }
            let _ = fs::remove_file(&oldest);
            total = total.saturating_sub(size);
        }
    }

    /// Oldest spooled batch, if any, with its path (remove it after successful delivery).
    pub fn peek(&self) -> Option<(PathBuf, Vec<serde_json::Value>)> {
        for path in self.files() {
            match fs::read(&path)
                .ok()
                .and_then(|raw| serde_json::from_slice(&raw).ok())
            {
                Some(batch) => return Some((path, batch)),
                None => {
                    let _ = fs::remove_file(&path); // corrupt file: discard
                }
            }
        }
        None
    }

    pub fn ack(&self, path: &Path) {
        let _ = fs::remove_file(path);
    }

    pub fn depth(&self) -> u64 {
        self.files().len() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventFactory, Host};
    use chrono::Utc;

    #[test]
    fn spool_is_fifo_and_bounded() {
        let dir = std::env::temp_dir().join(format!("aegis-spool-{}", uuid::Uuid::now_v7()));
        let f = EventFactory::new(
            Host {
                hostname: "h".into(),
                os: None,
                ip: vec![],
            },
            0,
        );
        let batch: Vec<Event> = (0..10)
            .map(|_| f.event("system", "agent_start", Utc::now()))
            .collect();
        let size = serde_json::to_vec(&batch).unwrap().len() as u64;
        let mut spool = Spool::open(&dir, size + size / 2).unwrap();
        spool.push(&batch).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        spool.push(&batch[..5]).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        spool.push(&batch[..3]).unwrap(); // exceeds limit: oldest (10 events) dropped
        assert_eq!(spool.dropped_events, 10);
        let (path, first) = spool.peek().unwrap();
        assert_eq!(first.len(), 5);
        spool.ack(&path);
        assert_eq!(spool.peek().unwrap().1.len(), 3);
        assert_eq!(spool.depth(), 1);
    }
}
