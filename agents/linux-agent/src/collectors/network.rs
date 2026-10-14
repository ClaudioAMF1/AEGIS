//! TCP connections from /proc/net/tcp{,6}. Only metadata (addresses, ports, owning process) is
//! collected — never payloads. New ESTABLISHED sockets are reported once; a socket whose local
//! port is a listening port is an inbound `accept`, otherwise an outbound `connect`.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use chrono::Utc;

use crate::collectors::Sink;
use crate::event::{EventFactory, Network, Process, User};
use crate::procfs::ProcFs;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Socket {
    pub local: (IpAddr, u16),
    pub remote: (IpAddr, u16),
    pub state: u8,
    pub inode: u64,
    pub uid: u32,
    pub v6: bool,
}

const ESTABLISHED: u8 = 0x01;
const LISTEN: u8 = 0x0A;

fn parse_v4(hex: &str) -> Option<IpAddr> {
    let raw = u32::from_str_radix(hex, 16).ok()?;
    Some(IpAddr::V4(Ipv4Addr::from(raw.swap_bytes())))
}

fn parse_v6(hex: &str) -> Option<IpAddr> {
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for word in 0..4 {
        let chunk = u32::from_str_radix(&hex[word * 8..word * 8 + 8], 16).ok()?;
        bytes[word * 4..word * 4 + 4].copy_from_slice(&chunk.to_le_bytes());
    }
    let addr = Ipv6Addr::from(bytes);
    Some(match addr.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(addr),
    })
}

fn parse_endpoint(text: &str, v6: bool) -> Option<(IpAddr, u16)> {
    let (addr, port) = text.split_once(':')?;
    let ip = if v6 { parse_v6(addr)? } else { parse_v4(addr)? };
    Some((ip, u16::from_str_radix(port, 16).ok()?))
}

pub fn parse_table(text: &str, v6: bool) -> Vec<Socket> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            Some(Socket {
                local: parse_endpoint(f.get(1)?, v6)?,
                remote: parse_endpoint(f.get(2)?, v6)?,
                state: u8::from_str_radix(f.get(3)?, 16).ok()?,
                uid: f.get(7)?.parse().ok()?,
                inode: f.get(9)?.parse().ok()?,
                v6,
            })
        })
        .collect()
}

pub struct NetworkCollector {
    procfs: ProcFs,
    users: HashMap<u32, String>,
    ignore_loopback: bool,
    seen: HashSet<u64>,
}

impl NetworkCollector {
    pub fn new(procfs: ProcFs, users: HashMap<u32, String>, ignore_loopback: bool) -> Self {
        Self {
            procfs,
            users,
            ignore_loopback,
            seen: HashSet::new(),
        }
    }

    fn sockets(&self) -> Vec<Socket> {
        let mut all = parse_table(&self.procfs.read("net/tcp").unwrap_or_default(), false);
        all.extend(parse_table(
            &self.procfs.read("net/tcp6").unwrap_or_default(),
            true,
        ));
        all
    }

    /// inode -> pid, scanning /proc/*/fd only for the inodes we need.
    fn owners(&self, wanted: &HashSet<u64>) -> HashMap<u64, u32> {
        let mut owners = HashMap::new();
        if wanted.is_empty() {
            return owners;
        }
        for pid in self.procfs.pids() {
            let Ok(fds) = fs::read_dir(self.procfs.root().join(pid.to_string()).join("fd")) else {
                continue;
            };
            for fd in fds.flatten() {
                if let Ok(target) = fs::read_link(fd.path()) {
                    let target = target.to_string_lossy();
                    if let Some(inode) = target
                        .strip_prefix("socket:[")
                        .and_then(|s| s.strip_suffix(']'))
                        .and_then(|s| s.parse::<u64>().ok())
                        && wanted.contains(&inode)
                    {
                        owners.insert(inode, pid);
                    }
                }
            }
            if owners.len() == wanted.len() {
                break;
            }
        }
        owners
    }

    pub fn prime(&mut self) {
        self.seen = self
            .sockets()
            .into_iter()
            .filter(|s| s.state == ESTABLISHED)
            .map(|s| s.inode)
            .collect();
    }

    pub fn poll(&mut self, factory: &EventFactory) -> Vec<crate::event::Event> {
        let sockets = self.sockets();
        let listening: HashSet<u16> = sockets
            .iter()
            .filter(|s| s.state == LISTEN)
            .map(|s| s.local.1)
            .collect();
        let established: Vec<&Socket> = sockets
            .iter()
            .filter(|s| s.state == ESTABLISHED && s.inode != 0)
            .filter(|s| !(self.ignore_loopback && s.remote.0.is_loopback()))
            .collect();
        let fresh: Vec<&&Socket> = established
            .iter()
            .filter(|s| !self.seen.contains(&s.inode))
            .collect();
        let owners = self.owners(&fresh.iter().map(|s| s.inode).collect());
        let mut events = Vec::new();
        for socket in fresh {
            let inbound = listening.contains(&socket.local.1);
            let mut event = factory.event(
                "network",
                if inbound { "accept" } else { "connect" },
                Utc::now(),
            );
            let (src, dst) = if inbound {
                (socket.remote, socket.local)
            } else {
                (socket.local, socket.remote)
            };
            event.network = Some(Network {
                direction: if inbound { "inbound" } else { "outbound" },
                protocol: if socket.v6 { "tcp6" } else { "tcp" },
                src_ip: src.0.to_string(),
                src_port: src.1,
                dst_ip: dst.0.to_string(),
                dst_port: dst.1,
                state: Some("established".into()),
            });
            event.user = Some(User {
                name: self
                    .users
                    .get(&socket.uid)
                    .cloned()
                    .unwrap_or_else(|| socket.uid.to_string()),
                uid: Some(socket.uid),
            });
            if let Some(info) = owners
                .get(&socket.inode)
                .and_then(|pid| self.procfs.process(*pid))
            {
                event.process = Some(Process {
                    pid: info.pid,
                    ppid: Some(info.ppid),
                    name: info.name,
                    executable: info.executable,
                    ..Process::default()
                });
            }
            events.push(event);
        }
        self.seen = established.iter().map(|s| s.inode).collect();
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

    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1111 1 0000000000000000 100 0 0 10 0
   1: 0B00140A:C9A8 176433C6:115C 01 00000000:00000000 00:00000000 00000000  1001        0 2222 1 0000000000000000 20 4 30 10 -1
   2: 0B00140A:0016 2D7100CB:D431 01 00000000:00000000 00:00000000 00000000     0        0 3333 1 0000000000000000 20 4 30 10 -1";

    #[test]
    fn parses_ipv4_table() {
        let table = TCP;
        let sockets = parse_table(table, false);
        assert_eq!(sockets.len(), 3);
        assert_eq!(sockets[0].state, LISTEN);
        assert_eq!(sockets[0].local.1, 22);
        assert_eq!(sockets[1].local, ("10.20.0.11".parse().unwrap(), 51624));
        assert_eq!(sockets[1].remote, ("198.51.100.23".parse().unwrap(), 4444));
        assert_eq!(
            sockets[2].remote.0,
            "203.0.113.45".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn parses_ipv4_mapped_ipv6() {
        let ip = parse_v6("0000000000000000FFFF00000B00140A").unwrap();
        assert_eq!(ip, "10.20.0.11".parse::<IpAddr>().unwrap());
        let loopback = parse_v6("00000000000000000000000001000000").unwrap();
        assert!(loopback.is_loopback());
    }

    #[test]
    fn classifies_direction_and_reports_once() {
        let dir = std::env::temp_dir().join(format!("aegis-net-{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(dir.join("net")).unwrap();
        fs::write(
            dir.join("net/tcp"),
            TCP.lines().take(2).collect::<Vec<_>>().join("\n"),
        )
        .unwrap();
        let mut collector = NetworkCollector::new(ProcFs::new(&dir), HashMap::new(), true);
        let factory = EventFactory::new(
            crate::event::Host {
                hostname: "h".into(),
                os: None,
                ip: vec![],
            },
            0,
        );
        collector.prime();
        fs::write(dir.join("net/tcp"), TCP).unwrap();
        let events = collector.poll(&factory);
        assert_eq!(events.len(), 2);
        let outbound = events.iter().find(|e| e.action == "connect").unwrap();
        assert_eq!(outbound.network.as_ref().unwrap().dst_port, 4444);
        let inbound = events.iter().find(|e| e.action == "accept").unwrap();
        let n = inbound.network.as_ref().unwrap();
        assert_eq!((n.src_ip.as_str(), n.dst_port), ("203.0.113.45", 22));
        assert!(collector.poll(&factory).is_empty());
    }
}
