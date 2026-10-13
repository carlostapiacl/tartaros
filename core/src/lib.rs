//! seisin-sandbox-core — the policy model and backend interface.
//!
//! This crate is the differentiator: it defines *what* seisin-sandbox enforces
//! (the policy, including the trust-handoff set), independent of *how* a given
//! OS enforces it (the backends). Backends are swappable; the policy is not.
//!
//! Nothing here is wired to a real OS yet — this is the shape the macOS and
//! Linux backends will implement. See `backends/`.

use std::path::PathBuf;

/// What a confined process may do with a filesystem path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
    /// Deny wins over any overlapping allow (see [`Policy`]).
    Deny,
}

/// One filesystem rule. A `Deny` over a path that falls inside a broader
/// `Write` is the carve-out the other sandboxes handle poorly (Landlock cannot
/// express it at all; Seatbelt/bwrap need ancestor protection to be safe).
#[derive(Debug, Clone)]
pub struct FsRule {
    pub path: PathBuf,
    pub access: Access,
    /// Apply to this path even if it does not exist yet (a deny must hold for a
    /// path the agent may still create).
    pub even_if_absent: bool,
}

/// Whether the confined process may reach the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Denied,
    /// Only the given loopback proxy port.
    ProxyOnly(u16),
    Allowed,
}

/// The set of files a *trusted tool outside the sandbox* later runs, loads, or
/// scans — the real escape surface. seisin-sandbox protects these at ANY depth
/// (nested repos and submodules included) and against ancestor renames, which
/// is what the measured competitors miss.
///
/// Returned as deny rules by [`Policy::trust_handoff_rules`].
pub const TRUST_HANDOFF_NAMES: &[&str] = &[
    ".git/hooks",
    ".git/config",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".vscode/tasks.json",
    ".envrc",
    // shell rc files and CI config are resolved per-root at policy build time.
];

/// A complete, backend-independent confinement policy.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    /// Roots the agent may write under.
    pub writable_roots: Vec<PathBuf>,
    /// Explicit filesystem rules; `Deny` always wins over an overlapping allow.
    pub fs_rules: Vec<FsRule>,
    pub network: Option<Network>,
    /// Deny any process-info / environment read of processes outside this
    /// sandbox (macOS `KERN_PROCARGS2`, Linux `/proc/<pid>`).
    pub isolate_process_info: bool,
}

impl Policy {
    /// Expand [`TRUST_HANDOFF_NAMES`] into concrete deny rules under each
    /// writable root, at every depth. TODO: walk for nested `.git/HEAD` markers
    /// and resolve shell rc / CI paths. This is the core job of the policy.
    pub fn trust_handoff_rules(&self) -> Vec<FsRule> {
        // Intentionally unimplemented: this is the first thing to build.
        Vec::new()
    }
}

/// Outcome of running a command under a backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunOutcome {
    /// Process exit code, or 128 + signal when killed by a signal.
    pub exit_code: i32,
}

/// An OS-specific enforcement engine. macOS (Seatbelt), Linux (Landlock/bwrap),
/// and an adapter over `@anthropic-ai/sandbox-runtime` each implement this.
pub trait Backend {
    /// Backend name, e.g. "macos-seatbelt".
    fn name(&self) -> &str;

    /// Reject a policy this backend cannot faithfully enforce, rather than
    /// running under-confined. Landlock, for example, must refuse a deny that
    /// overlaps an allow unless the policy was restructured to enumerate siblings.
    fn validate(&self, policy: &Policy) -> Result<(), PolicyError>;

    /// Run `command` confined by `policy`.
    fn run(&self, policy: &Policy, command: &[String]) -> Result<RunOutcome, RunError>;
}

/// A policy a backend cannot enforce as written.
#[derive(Debug, Clone)]
pub struct PolicyError {
    pub reason: String,
}

/// A failure while launching or confining the command.
#[derive(Debug, Clone)]
pub struct RunError {
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_beats_write_is_representable() {
        let p = Policy {
            writable_roots: vec![PathBuf::from("/work")],
            fs_rules: vec![FsRule {
                path: PathBuf::from("/work/nested/.git"),
                access: Access::Deny,
                even_if_absent: true,
            }],
            network: Some(Network::Denied),
            isolate_process_info: true,
        };
        assert_eq!(p.writable_roots.len(), 1);
        assert_eq!(p.fs_rules[0].access, Access::Deny);
    }
}
