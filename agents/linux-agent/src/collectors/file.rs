//! File changes in configured directories via inotify. Metadata only (path, mode, size).

use std::path::PathBuf;

use chrono::Utc;
use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;

use crate::collectors::Sink;
use crate::event::{EventFactory, File, clip};

pub fn action_for(mask: EventMask) -> Option<&'static str> {
    if mask.contains(EventMask::CREATE) || mask.contains(EventMask::MOVED_TO) {
        Some("create")
    } else if mask.contains(EventMask::DELETE) || mask.contains(EventMask::MOVED_FROM) {
        Some("delete")
    } else if mask.contains(EventMask::ATTRIB) {
        Some("chmod")
    } else if mask.contains(EventMask::CLOSE_WRITE) || mask.contains(EventMask::MODIFY) {
        Some("modify")
    } else {
        None
    }
}

/// Blocking loop (run on a dedicated thread). Coalesces MODIFY bursts by reporting CLOSE_WRITE.
pub fn run_blocking(
    paths: Vec<PathBuf>,
    factory: std::sync::Arc<EventFactory>,
    sink: Sink,
) -> anyhow::Result<()> {
    let mut inotify = Inotify::init()?;
    let mut watches: HashMap<WatchDescriptor, PathBuf> = HashMap::new();
    let mask = WatchMask::CREATE
        | WatchMask::DELETE
        | WatchMask::CLOSE_WRITE
        | WatchMask::ATTRIB
        | WatchMask::MOVED_FROM
        | WatchMask::MOVED_TO;
    for path in paths {
        match inotify.watches().add(&path, mask) {
            Ok(wd) => {
                watches.insert(wd, path);
            }
            Err(err) => tracing::debug!(path = %path.display(), %err, "not watching path"),
        }
    }
    if watches.is_empty() {
        tracing::warn!("file collector: no watchable paths");
        return Ok(());
    }
    let mut buffer = [0u8; 8192];
    loop {
        for item in inotify.read_events_blocking(&mut buffer)? {
            let Some(action) = action_for(item.mask) else {
                continue;
            };
            let Some(dir) = watches.get(&item.wd) else {
                continue;
            };
            let path = match item.name {
                Some(name) => dir.join(name),
                None => dir.clone(),
            };
            let metadata = std::fs::symlink_metadata(&path).ok();
            let mut event = factory.event("file", action, Utc::now());
            event.file = Some(File {
                path: clip(&path.to_string_lossy(), 1024),
                target_path: None,
                mode: metadata
                    .as_ref()
                    .map(|m| format!("{:o}", m.permissions().mode() & 0o7777)),
                size: metadata.as_ref().filter(|m| m.is_file()).map(|m| m.len()),
            });
            sink.emit(event);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_masks() {
        assert_eq!(action_for(EventMask::CREATE), Some("create"));
        assert_eq!(action_for(EventMask::MOVED_FROM), Some("delete"));
        assert_eq!(action_for(EventMask::CLOSE_WRITE), Some("modify"));
        assert_eq!(action_for(EventMask::ATTRIB), Some("chmod"));
        assert_eq!(action_for(EventMask::ACCESS), None);
    }
}
