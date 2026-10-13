//! macOS backend — generates a Seatbelt (sandbox-exec) profile from a
//! `seisin_sandbox_core::Policy` and runs the command under it.
//!
//! Informed by the Seatbelt profile vendored under `vendor/codex/` (OpenAI
//! Codex, Apache-2.0; see THIRD_PARTY_NOTICES.md) — specifically the
//! deny-by-default base and the ancestor move-blocking idea. This is our own
//! generator, hardened in two ways the original is not:
//!   1. the trust-handoff deny set and its ancestor protection are applied to
//!      EVERY protected path at any depth, via `Policy::trust_handoff_rules`;
//!   2. we never emit a `kern.proc.*` sysctl allow.

use seisin_sandbox_core::{Access, Backend, FsRule, Network, Policy, PolicyError, RunError, RunOutcome};
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct SeatbeltBackend;

impl Backend for SeatbeltBackend {
    fn name(&self) -> &str {
        "macos-seatbelt"
    }

    fn validate(&self, policy: &Policy) -> Result<(), PolicyError> {
        if policy.writable_roots.is_empty() {
            return Err(PolicyError { reason: "no writable roots".into() });
        }
        for r in &policy.writable_roots {
            if !r.is_absolute() {
                return Err(PolicyError {
                    reason: format!("writable root must be absolute: {}", r.display()),
                });
            }
        }
        Ok(())
    }

    fn run(&self, policy: &Policy, command: &[String]) -> Result<RunOutcome, RunError> {
        self.validate(policy).map_err(|e| RunError { reason: e.reason })?;
        if command.is_empty() {
            return Err(RunError { reason: "empty command".into() });
        }
        let profile = compile_profile(policy);
        let status = Command::new("/usr/bin/sandbox-exec")
            .arg("-p")
            .arg(&profile)
            .arg("--")
            .args(command)
            .status()
            .map_err(|e| RunError { reason: format!("spawning sandbox-exec: {e}") })?;

        let exit_code = exit_code_of(status);
        Ok(RunOutcome { exit_code })
    }
}

#[cfg(unix)]
fn exit_code_of(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    if let Some(code) = status.code() {
        code
    } else if let Some(sig) = status.signal() {
        128 + sig
    } else {
        -1
    }
}

#[cfg(not(unix))]
fn exit_code_of(status: std::process::ExitStatus) -> i32 {
    status.code().unwrap_or(-1)
}

/// Build the Seatbelt SBPL profile. In SBPL the LAST matching rule wins, so
/// every deny is emitted AFTER the broad allows, and the trust-handoff denies
/// cannot be re-allowed.
pub fn compile_profile(policy: &Policy) -> String {
    // Seatbelt matches real paths, so resolve symlinked roots (e.g. macOS
    // /var -> /private/var) before emitting. Trust-handoff paths are derived
    // from these roots, so canonicalizing here keeps allows and denies aligned.
    let roots: Vec<PathBuf> = policy
        .writable_roots
        .iter()
        .map(|r| r.canonicalize().unwrap_or_else(|_| r.clone()))
        .collect();
    let policy = &Policy { writable_roots: roots, ..policy.clone() };

    let mut p = String::new();
    p.push_str("(version 1)\n");
    p.push_str("(deny default)\n");

    // Enough to let ordinary tools (sh, git, python) run.
    p.push_str("(allow process-exec*)\n");
    p.push_str("(allow process-fork)\n");
    p.push_str("(allow file-read*)\n");
    p.push_str("(allow file-ioctl)\n");
    p.push_str("(allow file-write* (subpath \"/dev\"))\n");
    p.push_str("(allow signal (target self))\n");
    p.push_str("(allow mach-lookup)\n");

    // Process-info / environment isolation. We never allow `kern.proc.*`.
    // Other processes' args/env must not be reachable from inside the box.
    if policy.isolate_process_info {
        p.push_str("(allow process-info* (target self))\n");
    } else {
        p.push_str("(allow process-info*)\n");
    }
    // A minimal, procargs-free sysctl allow so tools can read hardware info.
    p.push_str("(allow sysctl-read\n");
    for name in ["hw.ncpu", "hw.activecpu", "hw.memsize", "hw.pagesize", "kern.ostype", "kern.osrelease", "kern.version", "kern.hostname"] {
        p.push_str(&format!("  (sysctl-name \"{name}\")\n"));
    }
    p.push_str(")\n");

    // Network.
    match policy.network.unwrap_or(Network::Denied) {
        Network::Denied => {}
        Network::ProxyOnly(port) => {
            p.push_str(&format!(
                "(allow network-outbound (remote ip \"localhost:{port}\"))\n"
            ));
        }
        Network::Allowed => {
            p.push_str("(allow network*)\n");
        }
    }

    // Writable roots.
    for root in &policy.writable_roots {
        p.push_str(&format!("(allow file-write* (subpath {}))\n", quote(root)));
    }

    // Denies LAST so they win. Explicit deny rules + the trust-handoff set.
    let mut denies: Vec<FsRule> = policy
        .fs_rules
        .iter()
        .filter(|r| r.access == Access::Deny)
        .cloned()
        .collect();
    denies.extend(policy.trust_handoff_rules());

    for rule in &denies {
        emit_deny(&mut p, &rule.path, &policy.writable_roots);
    }

    p
}

/// Deny write to a protected path, plus ancestor move-blocking: renaming any
/// ancestor up to (but not including) the writable root would relocate the
/// protected path out from under its deny, so unlink/rename is denied on each
/// ancestor and on the path itself. `file-write-unlink` is what rename/delete use.
fn emit_deny(p: &mut String, path: &Path, roots: &[PathBuf]) {
    p.push_str(&format!("(deny file-write* (subpath {}))\n", quote(path)));
    p.push_str(&format!("(deny file-write* (literal {}))\n", quote(path)));

    // Which root contains this path?
    let root = roots.iter().find(|r| path.starts_with(r));
    p.push_str(&format!("(deny file-write-unlink (literal {}))\n", quote(path)));
    if let Some(root) = root {
        let mut cur = path.parent();
        while let Some(dir) = cur {
            if dir == root.as_path() {
                break; // the root boundary is already enforced by not being writable outside
            }
            p.push_str(&format!("(deny file-write-unlink (literal {}))\n", quote(dir)));
            cur = dir.parent();
        }
    }
}

/// Quote a path as an SBPL string literal.
fn quote(path: &Path) -> String {
    let s = path.to_string_lossy();
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_has_no_kern_proc_and_denies_last() {
        let policy = Policy {
            writable_roots: vec![PathBuf::from("/work")],
            fs_rules: vec![FsRule {
                path: PathBuf::from("/work/nested/.git/hooks"),
                access: Access::Deny,
                even_if_absent: true,
            }],
            network: Some(Network::Denied),
            isolate_process_info: true,
        };
        let prof = compile_profile(&policy);
        assert!(!prof.contains("kern.proc"), "must never allow kern.proc.*");
        // the deny for the hooks dir appears after the writable-root allow
        let allow_at = prof.find("(allow file-write* (subpath \"/work\"))").unwrap();
        let deny_at = prof.find("(deny file-write* (subpath \"/work/nested/.git/hooks\"))").unwrap();
        assert!(deny_at > allow_at, "denies must come after allows (last match wins)");
        // ancestor move-blocking present
        assert!(prof.contains("(deny file-write-unlink (literal \"/work/nested/.git\"))"));
        assert!(prof.contains("(deny file-write-unlink (literal \"/work/nested\"))"));
    }
}
