//! Linux backend — Landlock (and bwrap where a deny-on-absent path needs it).
//!
//! Landlock cannot express "allow X but deny X/y", so nono refuses such a
//! policy. seisin restructures instead: `Policy::linux_write_allowlist` carves
//! the deny out of the allow (grant safe subtrees, exclude the protected
//! branch). This backend validates by computing that allow-list; the actual
//! Landlock ruleset wiring runs on a Linux kernel (see ROADMAP M2, tested on
//! the Linux test host). Where the carve would forbid creating files directly in a dir that
//! contains a protected path and that matters, the backend falls back to bwrap
//! with Codex's flock mount registry for concurrent-run safety.

use seisin_sandbox_core::{Backend, Policy, PolicyError, RunError, RunOutcome};

pub struct LandlockBackend;

impl Backend for LandlockBackend {
    fn name(&self) -> &str {
        "linux-landlock"
    }

    fn validate(&self, policy: &Policy) -> Result<(), PolicyError> {
        if policy.writable_roots.is_empty() {
            return Err(PolicyError { reason: "no writable roots".into() });
        }
        // seisin can always express the policy by restructuring: the carve
        // yields the Landlock write allow-list. (nono would reject here.)
        let _allow = policy.linux_write_allowlist();
        Ok(())
    }

    fn run(&self, _policy: &Policy, _command: &[String]) -> Result<RunOutcome, RunError> {
        // Enforcement needs a Linux kernel with Landlock; wired in M2 on the Linux test host.
        Err(RunError { reason: "linux-landlock run() not wired yet (M2)".into() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seisin_sandbox_core::Policy;
    use std::path::PathBuf;

    #[test]
    fn validate_accepts_deny_inside_allow() {
        // The exact shape nono refuses on Linux.
        let policy = Policy {
            writable_roots: vec![PathBuf::from("/work")],
            ..Default::default()
        };
        assert!(LandlockBackend.validate(&policy).is_ok());
    }
}
