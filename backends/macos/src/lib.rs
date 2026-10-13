//! macOS backend — generates a Seatbelt (sandbox-exec) profile from a
//! `tartaros_core::Policy` and runs the command under it.
//!
//! Informed by the Seatbelt profile vendored under `vendor/codex/` (OpenAI
//! Codex, Apache-2.0; see THIRD_PARTY_NOTICES.md) — specifically the
//! deny-by-default base and the ancestor move-blocking idea. This is our own
//! generator, hardened in two ways the original is not:
//!   1. the trust-handoff deny set and its ancestor protection are applied to
//!      EVERY protected path at any depth, via `Policy::trust_handoff_rules`;
//!   2. we never emit a `kern.proc.*` sysctl allow.

use tartaros_core::{
    Access, Backend, Collector, EffectSink, FsRule, Network, Policy, PolicyError, RunError,
    RunOutcome,
};
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
        use tartaros_core::VecSink;
        let child = self.spawn(policy, command)?;
        Ok(RunOutcome { exit_code: supervise(child, policy.timeout, &mut [], &mut VecSink::default()) })
    }
}

impl SeatbeltBackend {
    /// Spawn the confined command without waiting, so collectors can observe its
    /// process tree by pid while it runs (used by the CLI's `--log`).
    pub fn spawn(&self, policy: &Policy, command: &[String]) -> Result<std::process::Child, RunError> {
        self.validate(policy).map_err(|e| RunError { reason: e.reason })?;
        if command.is_empty() {
            return Err(RunError { reason: "empty command".into() });
        }
        let profile = compile_profile(policy);
        let mut cmd = Command::new("/usr/bin/sandbox-exec");
        cmd.arg("-p").arg(&profile).arg("--").args(command);
        let max_memory = policy.max_memory_bytes;
        let max_processes = policy.max_processes;
        let max_cpu = policy.max_cpu_secs;
        #[cfg(unix)]
        unsafe {
            use std::os::unix::process::CommandExt;
            cmd.pre_exec(move || {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                set_rlimit(libc::RLIMIT_AS as libc::c_int, max_memory)?;
                set_rlimit(libc::RLIMIT_NPROC as libc::c_int, max_processes)?;
                set_rlimit(libc::RLIMIT_CPU as libc::c_int, max_cpu)?;
                // Close every inherited fd >= 3, not a fixed 1024 cap (review P1):
                // use the current fd limit so high-numbered fds are closed too.
                let mut hi: libc::rlimit = std::mem::zeroed();
                let max_fd = if libc::getrlimit(libc::RLIMIT_NOFILE, &mut hi) == 0 && hi.rlim_cur != libc::RLIM_INFINITY {
                    (hi.rlim_cur as i32).min(1 << 20)
                } else {
                    1 << 16
                };
                for fd in 3..max_fd {
                    libc::close(fd);
                }
                Ok(())
            });
        }
        cmd.spawn().map_err(|e| RunError { reason: format!("spawning sandbox-exec: {e}") })
    }

    /// Run confined AND observe with collectors, under the SAME supervisor as
    /// `run` (timeout, limits, reaping). Observation never changes the guarantees
    /// (external review P0).
    pub fn run_observed<F>(
        &self,
        policy: &Policy,
        command: &[String],
        sink: &mut dyn EffectSink,
        make_collectors: F,
    ) -> Result<RunOutcome, RunError>
    where
        F: FnOnce(u32) -> Vec<Box<dyn Collector>>,
    {
        let child = self.spawn(policy, command)?;
        let mut cols = make_collectors(child.id());
        Ok(RunOutcome { exit_code: supervise(child, policy.timeout, &mut cols, sink) })
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

/// Apply one `setrlimit` (cur=max=limit) when set; a failure aborts the launch.
#[cfg(unix)]
fn set_rlimit(resource: libc::c_int, limit: Option<u64>) -> std::io::Result<()> {
    if let Some(v) = limit {
        let rl = libc::rlimit { rlim_cur: v as libc::rlim_t, rlim_max: v as libc::rlim_t };
        if unsafe { libc::setrlimit(resource as _, &rl) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Supervise the confined child: enforce the wall-clock timeout, then reap the
/// whole process group so no descendant is left behind.
#[cfg(unix)]
fn supervise(
    mut child: std::process::Child,
    timeout: Option<std::time::Duration>,
    collectors: &mut [Box<dyn Collector>],
    sink: &mut dyn EffectSink,
) -> i32 {
    use std::time::{Duration, Instant};
    let pid = child.id() as i32;
    let start = Instant::now();
    let kill_group = |sig: i32| unsafe { libc::kill(-pid, sig); };
    // Adaptive poll: start tight (short commands dominate) and back off to 50ms,
    // removing a fixed ~50ms per-launch latency. Cadence does not affect the
    // timeout/teardown guarantees.
    let mut poll_ms = 1u64;
    loop {
        for c in collectors.iter_mut() {
            c.poll(sink);
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                for c in collectors.iter_mut() {
                    c.poll(sink);
                }
                kill_group(libc::SIGKILL);
                return exit_code_of(status);
            }
            Ok(None) => {
                if let Some(t) = timeout {
                    if start.elapsed() >= t {
                        kill_group(libc::SIGTERM);
                        std::thread::sleep(Duration::from_millis(500));
                        kill_group(libc::SIGKILL);
                        let _ = child.wait();
                        kill_group(libc::SIGKILL);
                        return 124;
                    }
                }
                std::thread::sleep(Duration::from_millis(poll_ms));
                poll_ms = (poll_ms * 2).min(50);
            }
            Err(_) => return -1,
        }
    }
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
    // Specific loopback ports the role was granted — without opening all of
    // localhost. (Field-detected: a role needs 8001/8081/3307 but not 8787.)
    for port in &policy.local_ports {
        p.push_str(&format!("(allow network-outbound (remote ip \"localhost:{port}\"))\n"));
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

    // Secret read-denies (last, so they win over the broad file-read* allow).
    // Canonicalize: Seatbelt matches the real path (e.g. /tmp -> /private/tmp).
    for path in &policy.read_denies {
        let real = path.canonicalize().unwrap_or_else(|_| path.clone());
        p.push_str(&format!("(deny file-read* (subpath {}))\n", quote(&real)));
        p.push_str(&format!("(deny file-read* (literal {}))\n", quote(&real)));
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
            ..Default::default()
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

    #[test]
    fn local_ports_open_only_the_granted_ports() {
        let policy = Policy {
            writable_roots: vec![PathBuf::from("/work")],
            local_ports: vec![8001, 8081],
            ..Default::default()
        };
        let prof = compile_profile(&policy);
        assert!(prof.contains("(allow network-outbound (remote ip \"localhost:8001\"))"));
        assert!(prof.contains("(allow network-outbound (remote ip \"localhost:8081\"))"));
        assert!(!prof.contains("localhost:8787"));
        assert!(!prof.contains("(allow network*)"));
    }
}
