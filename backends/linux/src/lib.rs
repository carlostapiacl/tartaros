//! Linux backend — Landlock (and bwrap where a deny-on-absent path needs it).
//!
//! Landlock cannot express a deny that overlaps a broader allow, so this
//! backend's `validate` must reject such a policy (or the policy layer must
//! restructure it to enumerate siblings). Where bwrap is used for deny-on-
//! not-yet-existing paths, adopt Codex's flock-based mount registry to survive
//! overlapping concurrent runs (our report #4 against sandbox-runtime).
//!
//! Not implemented yet.

use seisin_sandbox_core::{Backend, Policy, PolicyError, RunError, RunOutcome};

pub struct LandlockBackend;

impl Backend for LandlockBackend {
    fn name(&self) -> &str {
        "linux-landlock"
    }

    fn validate(&self, _policy: &Policy) -> Result<(), PolicyError> {
        Err(PolicyError { reason: "linux-landlock backend not implemented yet".into() })
    }

    fn run(&self, _policy: &Policy, _command: &[String]) -> Result<RunOutcome, RunError> {
        Err(RunError { reason: "linux-landlock backend not implemented yet".into() })
    }
}
