//! Native Windows backend: an AppContainer with no capabilities, grant-only NTFS
//! ACLs, a private desktop and a kill-on-close job object.
//!
//! The model comes from the W0 spike (docs/windows-backend.md § W0 results): an
//! AppContainer is held by what its SID is GRANTED, not by what is denied, so a
//! protected path is one the container's grant does not reach (a protected DACL
//! without the container's ACE), never a deny ACE.
//!
//! Status: W1, fail-closed. Every policy field this backend cannot enforce yet is
//! refused by `validate`, never silently dropped.

use std::path::{Path, PathBuf};
use tartaros_core::{Access, Backend, Network, Policy, PolicyError, RunError, RunOutcome};

#[cfg(windows)]
mod sys;

/// What the container gets on one path. Applied in this order, so a deeper or
/// later rule (a protect inside a grant) wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grant {
    /// Writable root: read/write/delete below it, no DELETE on the root itself,
    /// never FILE_DELETE_CHILD.
    Write,
    /// Inheritable read/execute.
    Read,
    /// Read/execute on this file only (the program being launched).
    ExecFile,
    /// Ancestor of a protected path: the container cannot delete or rename it;
    /// its children keep the write grant.
    Pin,
    /// Trust-handoff / write-deny: protected DACL, container keeps read only.
    ProtectReadOnly,
    /// Read-deny: protected DACL, the container gets nothing.
    ProtectNoAccess,
}

/// The DACL changes a policy compiles to, in application order. Pure, so it can
/// be unit-tested on any OS.
pub fn acl_plan(policy: &Policy, program: Option<&Path>) -> Vec<(PathBuf, Grant)> {
    let mut plan: Vec<(PathBuf, Grant)> = Vec::new();
    for r in &policy.writable_roots {
        plan.push((r.clone(), Grant::Write));
    }
    for r in &policy.read_allows {
        plan.push((r.clone(), Grant::Read));
    }
    if let Some(p) = program {
        if !policy.writable_roots.iter().chain(&policy.read_allows).any(|r| p.starts_with(r)) {
            plan.push((p.to_path_buf(), Grant::ExecFile));
        }
    }

    // Write-protected paths: the trust-handoff set plus explicit write-denies.
    // Only paths that exist get an ACE (an ACE cannot name a missing object);
    // absent ones are covered by `materialize_absent_handoff` or stay the
    // documented residual.
    let mut protect: Vec<PathBuf> = policy
        .trust_handoff_rules()
        .into_iter()
        .chain(policy.fs_rules.iter().cloned())
        .filter(|r| r.access == Access::Deny)
        .map(|r| r.path)
        .filter(|p| p.exists())
        .collect();
    protect.sort();
    protect.dedup();

    // Pin every ancestor between its writable root and the protected path, so
    // the path can't be moved away and recreated unprotected (rule #3).
    let mut pins: Vec<PathBuf> = Vec::new();
    for p in &protect {
        if let Some(root) = policy.writable_roots.iter().find(|r| p.starts_with(r)) {
            let mut a = p.parent();
            while let Some(dir) = a {
                if dir == root.as_path() || !dir.starts_with(root) {
                    break;
                }
                if !protect.iter().any(|q| q == dir) && !pins.iter().any(|q| q == dir) {
                    pins.push(dir.to_path_buf());
                }
                a = dir.parent();
            }
        }
    }
    // Shallow first: a child's protected DACL must be built from its parent's
    // final state.
    pins.sort_by_key(|p| p.components().count());
    plan.extend(pins.into_iter().map(|p| (p, Grant::Pin)));
    plan.extend(protect.into_iter().map(|p| (p, Grant::ProtectReadOnly)));

    let mut denies: Vec<PathBuf> = policy.read_denies.iter().filter(|p| p.exists()).cloned().collect();
    denies.sort_by_key(|p| p.components().count());
    plan.extend(denies.into_iter().map(|p| (p, Grant::ProtectNoAccess)));
    plan
}

/// Environment variables Windows programs need to start at all (Winsock fails
/// without `SystemRoot`, cmd without `COMSPEC`). None carries a credential.
/// `USERPROFILE`/`LOCALAPPDATA`/`APPDATA` are required by CreateProcess itself for
/// an AppContainer: it rewrites them to the container's folder, and fails with
/// ERROR_ENVVAR_NOT_FOUND (203) when they are missing (measured).
pub const WINDOWS_ENV_BASELINE: &[&str] = &[
    "SystemRoot", "windir", "SystemDrive", "COMSPEC", "PATHEXT", "OS",
    "USERPROFILE", "LOCALAPPDATA", "APPDATA",
    "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "ProgramFiles",
    "ProgramFiles(x86)", "ProgramW6432", "CommonProgramFiles",
];

pub struct AppContainerBackend;

impl Backend for AppContainerBackend {
    fn name(&self) -> &str {
        "windows-appcontainer"
    }

    fn validate(&self, policy: &Policy) -> Result<(), PolicyError> {
        if !cfg!(windows) {
            return Err(PolicyError { reason: "the Windows backend only runs on Windows".into() });
        }
        if policy.writable_roots.is_empty() {
            return Err(PolicyError { reason: "no writable roots".into() });
        }
        for r in policy.writable_roots.iter().chain(&policy.read_allows).chain(&policy.read_denies) {
            if !r.is_absolute() {
                return Err(PolicyError { reason: format!("path must be absolute: {}", r.display()) });
            }
        }
        policy.check_symlinked_roots().map_err(|reason| PolicyError { reason })?;
        let mut unsupported: Vec<&str> = Vec::new();
        match policy.network {
            None | Some(Network::Denied) => {}
            Some(Network::ProxyOnly(_)) | Some(Network::Allowed) => {
                unsupported.push("network other than denied (broker channel is W2)")
            }
        }
        if !policy.allow_domains.is_empty() || !policy.allowed_hosts.is_empty() || !policy.local_ports.is_empty() {
            unsupported.push("--allow-domain / allowed hosts / local ports (W2)");
        }
        if policy.isolate_pids {
            unsupported.push("--isolate-pids (no PID namespace; process listing not yet measured)");
        }
        if policy.isolate_process_info {
            unsupported.push("process-info isolation (not yet measured)");
        }
        if policy.harden_syscalls || policy.strict {
            unsupported.push("--seccomp-strict / strict (mitigation policies not built yet)");
        }
        if policy.deny_unix_sockets || !policy.allow_unix_socket_paths.is_empty() || !policy.unix_socket_subpaths.is_empty() {
            unsupported.push("AF_UNIX socket rules");
        }
        if !policy.glob_denies.is_empty() {
            unsupported.push("glob denies");
        }
        if !policy.allow_mach_lookup.is_empty() || !policy.allow_mach_register.is_empty() {
            unsupported.push("Mach services (macOS only)");
        }
        if policy.egress_netns.is_some() {
            unsupported.push("egress network namespace (Linux only)");
        }
        if policy.private_tmp || policy.browser {
            unsupported.push("private tmp / browser profile");
        }
        if !unsupported.is_empty() {
            return Err(PolicyError {
                reason: format!("unsupported on Windows (cannot be enforced here): {}", unsupported.join(", ")),
            });
        }
        // isolate_network is satisfied by construction: no network capability.
        Ok(())
    }

    fn run(&self, policy: &Policy, command: &[String]) -> Result<RunOutcome, RunError> {
        self.validate(policy).map_err(|e| RunError { reason: e.reason })?;
        if command.is_empty() {
            return Err(RunError { reason: "empty command".into() });
        }
        #[cfg(windows)]
        {
            sys::run(policy, command)
        }
        #[cfg(not(windows))]
        {
            Err(RunError { reason: "the Windows backend only runs on Windows".into() })
        }
    }
}

/// Whether the current process runs elevated (an admin token). The bench uses it
/// for the `admin` requirement.
pub fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        sys::is_elevated()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("tartaros-win-plan-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d.canonicalize().unwrap()
    }

    #[test]
    fn handoff_gets_pinned_ancestors_and_read_only_protect() {
        let root = tmp("pin");
        fs::create_dir_all(root.join("a/nested/.git/hooks")).unwrap();
        fs::write(root.join("a/nested/.git/config"), "").unwrap();
        let p = Policy { writable_roots: vec![root.clone()], ..Default::default() };
        let plan = acl_plan(&p, None);
        assert_eq!(plan[0], (root.clone(), Grant::Write));
        let pins: Vec<_> = plan.iter().filter(|(_, g)| *g == Grant::Pin).map(|(p, _)| p.clone()).collect();
        assert_eq!(pins, vec![root.join("a"), root.join("a/nested"), root.join("a/nested/.git")]);
        assert!(plan.contains(&(root.join("a/nested/.git/hooks"), Grant::ProtectReadOnly)));
        assert!(plan.contains(&(root.join("a/nested/.git/config"), Grant::ProtectReadOnly)));
        // the root itself is never pinned (it has its own no-DELETE grant)
        assert!(!pins.contains(&root));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn read_deny_comes_last_and_absent_paths_are_skipped() {
        let root = tmp("deny");
        fs::create_dir_all(root.join("secrets")).unwrap();
        let p = Policy {
            writable_roots: vec![root.clone()],
            read_denies: vec![root.join("secrets"), root.join("missing")],
            ..Default::default()
        };
        let plan = acl_plan(&p, None);
        assert_eq!(plan.last().unwrap(), &(root.join("secrets"), Grant::ProtectNoAccess));
        assert!(!plan.iter().any(|(p, _)| p.ends_with("missing")));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn program_outside_grants_gets_exec_on_the_file_only() {
        let root = tmp("exec");
        let p = Policy { writable_roots: vec![root.clone()], ..Default::default() };
        let prog = PathBuf::from("/opt/tools/busybox.exe");
        let plan = acl_plan(&p, Some(&prog));
        assert!(plan.contains(&(prog, Grant::ExecFile)));
        let inside = root.join("bin/sh.exe");
        assert!(!acl_plan(&p, Some(&inside)).iter().any(|(_, g)| *g == Grant::ExecFile));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn validate_refuses_what_it_cannot_enforce() {
        let p = Policy {
            writable_roots: vec![std::env::temp_dir()],
            isolate_pids: true,
            ..Default::default()
        };
        assert!(AppContainerBackend.validate(&p).is_err());
    }
}
