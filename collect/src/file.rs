//! File collector — notices which files the agent's process tree opens for
//! WRITING, the symmetric sibling of [`SecretCollector`](crate::SecretCollector)
//! (which watches reads). A write-open is classified relative to the territory:
//! under a writable root it is within-territory (ordinary work), anywhere else it
//! is a reach outside (e.g. a write to `/dev` or a path the carve granted outside
//! the declared roots).
//!
//! Honest scope: this OBSERVES opened write fds, so it records writes the policy
//! ALLOWED. A write the policy *denies* (outside the roots, or to a trust-handoff
//! path) is blocked by enforcement before the fd ever opens, so it is enforced,
//! not logged — the effect log is observation, never the enforcement boundary.
//! Like the other collectors it samples the process tree, so a very short-lived
//! write between polls can be missed.

use tartaros_core::{Axis, Collector, Direction, EffectEvent, EffectSink, Outcome};
use std::collections::HashSet;

use crate::proc;

pub struct FileCollector {
    role: String,
    root_pid: u32,
    /// Writable roots as strings, for the within/outside-territory decision.
    roots: Vec<String>,
    seen: HashSet<String>,
}

impl FileCollector {
    pub fn new(role: impl Into<String>, root_pid: u32, roots: Vec<String>) -> Self {
        FileCollector { role: role.into(), root_pid, roots, seen: HashSet::new() }
    }

    pub fn for_policy(root_pid: u32, policy: &tartaros_core::Policy) -> Self {
        let roots = policy
            .writable_roots
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        Self::new(policy.role.clone(), root_pid, roots)
    }

    /// Pure: a write-open target becomes an event; direction is within-territory
    /// iff the path is under a writable root, else a reach outside.
    fn classify(&self, target: &str) -> EffectEvent {
        let within = self.roots.iter().any(|r| target == r || target.starts_with(&format!("{r}/")));
        let dir = if within { Direction::WithinTerritory } else { Direction::OutsideTerritory };
        EffectEvent::now(
            self.role.clone(),
            Axis::File,
            "write-open",
            target.to_string(),
            dir,
            Outcome::Attempted,
            "file/fd",
        )
    }
}

impl Collector for FileCollector {
    fn name(&self) -> &str {
        "file/fd"
    }

    fn poll(&mut self, sink: &mut dyn EffectSink) {
        for pid in proc::process_tree(self.root_pid) {
            for (_fd, target) in proc::write_fd_targets(pid) {
                if self.seen.contains(&target) {
                    continue;
                }
                self.seen.insert(target.clone());
                let ev = self.classify(&target);
                sink.emit(&ev);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn within_vs_outside_territory() {
        let c = FileCollector::new("qa", 0, vec!["/repo".into()]);
        let inside = c.classify("/repo/src/out.txt");
        assert_eq!(inside.axis, Axis::File);
        assert_eq!(inside.action, "write-open");
        assert_eq!(inside.direction, Direction::WithinTerritory);
        // a prefix that is not a path boundary must NOT count as within
        let sibling = c.classify("/repository/evil");
        assert_eq!(sibling.direction, Direction::OutsideTerritory);
        // a genuinely outside path (e.g. /dev or /tmp) is a reach outside
        let outside = c.classify("/dev/null");
        assert_eq!(outside.direction, Direction::OutsideTerritory);
    }

    #[test]
    fn root_itself_is_within() {
        let c = FileCollector::new("qa", 0, vec!["/repo".into()]);
        assert_eq!(c.classify("/repo").direction, Direction::WithinTerritory);
    }
}
