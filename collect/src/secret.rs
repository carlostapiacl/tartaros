//! Secret collector — notices when the agent's process tree holds an open fd to
//! a known secret location (`~/.ssh`, `~/.aws`, `.env`, keychains, …). Reading a
//! secret is worth recording even when the policy allowed it: it is the data a
//! later exfil connect would carry.

use seisin_sandbox_core::catalog::looks_like_secret;
use seisin_sandbox_core::{Axis, Collector, Direction, EffectEvent, EffectSink, Outcome};
use std::collections::HashSet;

use crate::proc;

pub struct SecretCollector {
    role: String,
    root_pid: u32,
    seen: HashSet<String>,
}

impl SecretCollector {
    pub fn new(role: impl Into<String>, root_pid: u32) -> Self {
        SecretCollector { role: role.into(), root_pid, seen: HashSet::new() }
    }

    pub fn for_policy(root_pid: u32, policy: &seisin_sandbox_core::Policy) -> Self {
        Self::new(policy.role.clone(), root_pid)
    }

    /// Pure: an open-fd target becomes an event iff it reaches a secret.
    fn classify(&self, target: &str) -> Option<EffectEvent> {
        if looks_like_secret(target) {
            Some(EffectEvent::now(
                self.role.clone(),
                Axis::Secret,
                "read",
                target.to_string(),
                Direction::OutsideTerritory,
                Outcome::Attempted,
                "secret/fd",
            ))
        } else {
            None
        }
    }
}

impl Collector for SecretCollector {
    fn name(&self) -> &str {
        "secret/fd"
    }

    fn poll(&mut self, sink: &mut dyn EffectSink) {
        for pid in proc::process_tree(self.root_pid) {
            for (_fd, target) in proc::fd_targets(pid) {
                if self.seen.contains(&target) {
                    continue;
                }
                if let Some(ev) = self.classify(&target) {
                    self.seen.insert(target);
                    sink.emit(&ev);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seisin_sandbox_core::{Axis, Direction};

    #[test]
    fn flags_secret_fd_only() {
        let c = SecretCollector::new("qa", 0);
        assert!(c.classify("/repo/src/main.rs").is_none());
        let ev = c.classify("/home/x/.ssh/id_ed25519").expect("secret");
        assert_eq!(ev.axis, Axis::Secret);
        assert_eq!(ev.direction, Direction::OutsideTerritory);
        assert_eq!(ev.action, "read");
    }
}
