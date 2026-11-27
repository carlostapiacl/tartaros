//! The backend interface: what a backend runs a policy with, and what it returns.

use crate::Policy;

/// Outcome of running a command under a backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunOutcome {
    /// Process exit code, or 128 + signal when killed by a signal.
    pub exit_code: i32,
}

/// An OS-specific enforcement engine.
pub trait Backend {
    fn name(&self) -> &str;

    /// Reject a policy this backend cannot faithfully enforce, rather than
    /// running under-confined.
    fn validate(&self, policy: &Policy) -> Result<(), PolicyError>;

    /// Run `command` confined by `policy`.
    fn run(&self, policy: &Policy, command: &[String]) -> Result<RunOutcome, RunError>;
}

#[derive(Debug, Clone)]
pub struct PolicyError {
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct RunError {
    pub reason: String,
}
