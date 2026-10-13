//! Network collector — what the agent's process tree reaches toward the network.
//!
//! On Linux it reads `/proc/net/tcp`(6) and attributes sockets to the watched
//! pids via their fd socket inodes, so a burst of connects (a port scan) shows
//! up as many outside-territory events. Pure parsing is unit-tested; the live
//! read is Linux-only. macOS (lsof) is a planned sibling collector.

use seisin_sandbox_core::catalog::endpoint_direction;
use seisin_sandbox_core::{Axis, Collector, EffectEvent, EffectSink, Outcome};
use std::collections::HashSet;

/// A remote endpoint seen in a socket table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub ip: String,
    pub port: u16,
    /// The socket's inode, used to attribute it to a pid.
    pub inode: u64,
}

/// Observes the network reach of a set of pids.
pub struct NetworkCollector {
    role: String,
    pids: Vec<u32>,
    within_ports: Vec<u16>,
    allowed_hosts: Vec<String>,
    /// endpoints already reported, so poll() only emits new ones.
    seen: HashSet<(String, u16)>,
}

impl NetworkCollector {
    pub fn new(
        role: impl Into<String>,
        pids: Vec<u32>,
        within_ports: Vec<u16>,
        allowed_hosts: Vec<String>,
    ) -> Self {
        NetworkCollector {
            role: role.into(),
            pids,
            within_ports,
            allowed_hosts,
            seen: HashSet::new(),
        }
    }

    /// Turn an observed endpoint into an event (classifying direction). Pure, so
    /// it is testable without touching /proc.
    fn event_for(&self, ep: &Endpoint) -> EffectEvent {
        let dir = endpoint_direction(&ep.ip, ep.port, &self.within_ports, &self.allowed_hosts);
        EffectEvent::now(
            self.role.clone(),
            Axis::Network,
            "connect",
            format!("{}:{}", ep.ip, ep.port),
            dir,
            // A collector observes; it does not know the wall's verdict.
            Outcome::Attempted,
            "net/proc",
        )
    }
}

impl Collector for NetworkCollector {
    fn name(&self) -> &str {
        "net/proc"
    }

    fn poll(&mut self, sink: &mut dyn EffectSink) {
        for ep in observe(&self.pids) {
            let key = (ep.ip.clone(), ep.port);
            if self.seen.insert(key) {
                sink.emit(&self.event_for(&ep));
            }
        }
    }
}

/// Observe current remote endpoints for the given pids. Linux: real; otherwise
/// empty (a macOS lsof collector is the planned sibling).
#[cfg(target_os = "linux")]
fn observe(pids: &[u32]) -> Vec<Endpoint> {
    let inodes = socket_inodes_for(pids);
    let mut out = Vec::new();
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(contents) = std::fs::read_to_string(path) {
            for ep in parse_proc_net_tcp(&contents) {
                if inodes.contains(&ep.inode) {
                    out.push(ep);
                }
            }
        }
    }
    out
}

#[cfg(not(target_os = "linux"))]
fn observe(_pids: &[u32]) -> Vec<Endpoint> {
    Vec::new()
}

/// Collect the socket inodes owned by the pids (and reported fd links).
#[cfg(target_os = "linux")]
fn socket_inodes_for(pids: &[u32]) -> HashSet<u64> {
    let mut inodes = HashSet::new();
    for pid in pids {
        let fd_dir = format!("/proc/{pid}/fd");
        if let Ok(entries) = std::fs::read_dir(&fd_dir) {
            for e in entries.flatten() {
                if let Ok(target) = std::fs::read_link(e.path()) {
                    // links look like "socket:[12345]"
                    let t = target.to_string_lossy();
                    if let Some(rest) = t.strip_prefix("socket:[") {
                        if let Some(num) = rest.strip_suffix(']') {
                            if let Ok(n) = num.parse::<u64>() {
                                inodes.insert(n);
                            }
                        }
                    }
                }
            }
        }
    }
    inodes
}

/// Parse `/proc/net/tcp` or `/proc/net/tcp6`. Returns the *remote* endpoint and
/// socket inode of each non-listening row. Pure — unit-tested.
pub fn parse_proc_net_tcp(contents: &str) -> Vec<Endpoint> {
    let mut out = Vec::new();
    for line in contents.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // 0:sl 1:local 2:remote 3:st ... 9:inode
        if cols.len() < 10 {
            continue;
        }
        let remote = cols[2];
        let st = cols[3];
        // skip listening sockets (state 0A) and zero remotes
        if st == "0A" {
            continue;
        }
        let inode: u64 = cols[9].parse().unwrap_or(0);
        if let Some((ip, port)) = parse_hex_addr(remote) {
            if ip == "0.0.0.0" || port == 0 {
                continue;
            }
            out.push(Endpoint { ip, port, inode });
        }
    }
    out
}

/// "0100007F:1F90" -> ("127.0.0.1", 8080). Handles IPv4 and IPv6 hex forms.
fn parse_hex_addr(s: &str) -> Option<(String, u16)> {
    let (addr, port) = s.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    match addr.len() {
        8 => {
            // IPv4, little-endian hex
            let b = u32::from_str_radix(addr, 16).ok()?;
            let o = b.to_le_bytes();
            Some((format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3]), port))
        }
        32 => {
            // IPv6: 4 little-endian 32-bit words
            let mut groups = [0u16; 8];
            for i in 0..4 {
                let word = u32::from_str_radix(&addr[i * 8..i * 8 + 8], 16).ok()?;
                let le = word.to_le_bytes();
                groups[i * 2] = u16::from_be_bytes([le[0], le[1]]);
                groups[i * 2 + 1] = u16::from_be_bytes([le[2], le[3]]);
            }
            let ip = groups.iter().map(|g| format!("{g:x}")).collect::<Vec<_>>().join(":");
            Some((ip, port))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seisin_sandbox_core::{Direction, EffectSink, VecSink};

    #[test]
    fn parses_ipv4_remote_and_skips_listeners() {
        // header + one listener (0A) + one established connect to 8.8.8.8:53
        let sample = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 11111 1 0000 0
   1: 0100007F:C0DE 08080808:0035 01 00000000:00000000 00:00000000 00000000  1000        0 22222 1 0000 0";
        let eps = parse_proc_net_tcp(sample);
        assert_eq!(eps.len(), 1, "listener should be skipped");
        assert_eq!(eps[0].ip, "8.8.8.8");
        assert_eq!(eps[0].port, 0x35);
        assert_eq!(eps[0].inode, 22222);
    }

    #[test]
    fn emits_outside_event_for_external_endpoint() {
        let c = NetworkCollector::new("qa", vec![], vec![8001], vec![]);
        let ev = c.event_for(&Endpoint { ip: "8.8.8.8".into(), port: 53, inode: 1 });
        assert_eq!(ev.axis, Axis::Network);
        assert_eq!(ev.direction, Direction::OutsideTerritory);
        assert_eq!(ev.target, "8.8.8.8:53");
    }

    #[test]
    fn loopback_app_port_is_within() {
        let c = NetworkCollector::new("qa", vec![], vec![8001, 8081], vec![]);
        let ev = c.event_for(&Endpoint { ip: "127.0.0.1".into(), port: 8001, inode: 1 });
        assert_eq!(ev.direction, Direction::WithinTerritory);
    }

    #[test]
    fn dedup_only_new_endpoints() {
        // event_for + seen set behaviour via poll would need /proc; test seen set directly
        let mut c = NetworkCollector::new("qa", vec![], vec![], vec![]);
        let mut sink = VecSink::default();
        // simulate what poll does with two identical endpoints
        for _ in 0..2 {
            let ep = Endpoint { ip: "8.8.8.8".into(), port: 53, inode: 1 };
            let key = (ep.ip.clone(), ep.port);
            if c.seen.insert(key) {
                sink.emit(&c.event_for(&ep));
            }
        }
        assert_eq!(sink.events.len(), 1, "same endpoint reported once");
    }
}
