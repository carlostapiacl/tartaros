//! Process collector — two signals from the process tree:
//!   1. spawning a known network/exfil tool (curl, nc, ssh, …);
//!   2. reading another process's environment (an fd on `/proc/<pid>/environ`
//!      of a pid outside the agent's own tree) — the cross-process secret read.

use tartaros_core::catalog::is_exfil_tool;
use tartaros_core::{Axis, Collector, Direction, EffectEvent, EffectSink, Outcome};
use std::collections::HashSet;

use crate::proc;

pub struct ProcessCollector {
    role: String,
    root_pid: u32,
    seen_exec: HashSet<u32>,
    seen_env: HashSet<String>,
}

impl ProcessCollector {
    pub fn new(role: impl Into<String>, root_pid: u32) -> Self {
        ProcessCollector {
            role: role.into(),
            root_pid,
            seen_exec: HashSet::new(),
            seen_env: HashSet::new(),
        }
    }

    pub fn for_policy(root_pid: u32, policy: &tartaros_core::Policy) -> Self {
        Self::new(policy.role.clone(), root_pid)
    }

    fn exec_event(&self, exe: &str) -> Option<EffectEvent> {
        if is_exfil_tool(exe) {
            Some(EffectEvent::now(
                self.role.clone(),
                Axis::Process,
                "exec",
                exe.to_string(),
                Direction::OutsideTerritory,
                Outcome::Attempted,
                "process/proc",
            ))
        } else {
            None
        }
    }

    /// An fd target like "/proc/1234/environ" where 1234 is not in `own` is a
    /// read of another process's environment.
    fn env_read_event(&self, target: &str, own: &HashSet<u32>) -> Option<EffectEvent> {
        let rest = target.strip_prefix("/proc/")?;
        let (pid_str, tail) = rest.split_once('/')?;
        if tail != "environ" {
            return None;
        }
        let pid: u32 = pid_str.parse().ok()?;
        if own.contains(&pid) {
            return None;
        }
        Some(EffectEvent::now(
            self.role.clone(),
            Axis::Process,
            "read-env",
            target.to_string(),
            Direction::OutsideTerritory,
            Outcome::Attempted,
            "process/proc",
        ))
    }
}

impl Collector for ProcessCollector {
    fn name(&self) -> &str {
        "process/proc"
    }

    fn poll(&mut self, sink: &mut dyn EffectSink) {
        let tree: HashSet<u32> = proc::process_tree(self.root_pid).into_iter().collect();
        for &pid in &tree {
            if self.seen_exec.insert(pid) {
                if let Some(exe) = proc::exe(pid) {
                    if let Some(ev) = self.exec_event(&exe) {
                        sink.emit(&ev);
                    }
                }
            }
            for (_fd, target) in proc::fd_targets(pid) {
                if self.seen_env.contains(&target) {
                    continue;
                }
                if let Some(ev) = self.env_read_event(&target, &tree) {
                    self.seen_env.insert(target);
                    sink.emit(&ev);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_exfil_tool_exec() {
        let c = ProcessCollector::new("qa", 0);
        assert!(c.exec_event("/bin/ls").is_none());
        let ev = c.exec_event("/usr/bin/curl").expect("curl flagged");
        assert_eq!(ev.action, "exec");
        assert_eq!(ev.axis, Axis::Process);
    }

    #[test]
    fn flags_foreign_environ_read_only() {
        let own: HashSet<u32> = [100u32, 101].into_iter().collect();
        let c = ProcessCollector::new("qa", 100);
        // own environ: not flagged
        assert!(c.env_read_event("/proc/100/environ", &own).is_none());
        // someone else's environ: flagged
        let ev = c.env_read_event("/proc/999/environ", &own).expect("foreign env");
        assert_eq!(ev.action, "read-env");
        // not an environ fd: ignored
        assert!(c.env_read_event("/proc/999/status", &own).is_none());
    }
}
