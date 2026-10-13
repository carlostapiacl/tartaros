//! cgroup v2 setup, teardown and probing — the guaranteed resource caps and the
//! reliable `cgroup.kill` teardown — kept apart from the Landlock / seccomp /
//! namespace mechanisms. Linux-only (the whole module is gated).

use tartaros_core::Policy;

/// RAII owner of a per-run cgroup: tears it down (`cgroup.kill` + rmdir) on drop,
/// so the cgroup is cleaned up on EVERY exit path — including an early return
/// when `confined_command` or `spawn` fails after the cgroup was created (which
/// used to leak the directory).
pub(crate) struct Cgroup {
    dir: String,
}

impl Cgroup {
    pub(crate) fn dir(&self) -> &str {
        &self.dir
    }
    pub(crate) fn procs_path(&self) -> String {
        format!("{}/cgroup.procs", self.dir)
    }
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        destroy_cgroup(&self.dir);
    }
}

/// Create a cgroup v2 with the policy's pid/memory caps, if the cgroup fs is
/// writable (needs a delegated/privileged cgroup). Returns the cgroup dir, whose
/// `cgroup.procs` the child writes its pid into. Guaranteed regardless of uid/caps
/// — unlike RLIMIT_NPROC, which root bypasses (finding RES-1). Best-effort: on a
/// read-only cgroup fs it returns None and we fall back to setrlimit.
/// Warn (once per run) that a requested resource limit could not be enforced via
/// cgroups and has degraded to RLIMIT. `--max-procs` without a cgroup falls back
/// to RLIMIT_NPROC, which a process running as root (CAP_SYS_RESOURCE) can raise
/// and thus bypass (RES-1). Fail-loud, not fail-silent.
fn warn_cgroup_degraded(policy: &Policy) {
    if policy.max_processes.is_some() && !policy.strict {
        // In strict mode the caller aborts with a clear message, so the
        // "degraded" warning would be misleading — suppress it there.
        eprintln!(
            "tartaros: warning: cgroup v2 unavailable; --max-procs degraded to \
             RLIMIT_NPROC (best-effort, bypassable by root). Run on a cgroup-v2 host \
             with write access to /sys/fs/cgroup for a hard process cap."
        );
    }
}

pub(crate) fn create_cgroup(policy: &Policy) -> Option<Cgroup> {
    // Always build a per-run cgroup when the cgroup fs is usable — not only to
    // enforce pid/memory caps but for reliable teardown. On exit/timeout the
    // caller runs `cgroup.kill`, which reaps EVERY member, including a process
    // that double-forked and `setsid`'d out of the process group (which
    // kill(-pgid) misses). Without a cgroup such a daemon outlives the sandbox.
    // If the cgroup fs isn't usable we return None and fall back to
    // process-group teardown, warning only when a hard limit was actually asked.
    let base = "/sys/fs/cgroup";
    // enable controllers in the root subtree (best-effort).
    let _ = std::fs::write(format!("{base}/cgroup.subtree_control"), "+pids +memory");
    let dir = format!("{base}/tartaros-{}-{}", std::process::id(), now_nanos());
    if std::fs::create_dir(&dir).is_err() {
        warn_cgroup_degraded(policy);
        return None;
    }
    if let Some(n) = policy.max_processes {
        if std::fs::write(format!("{dir}/pids.max"), n.to_string()).is_err() {
            let _ = std::fs::remove_dir(&dir);
            warn_cgroup_degraded(policy);
            return None;
        }
    }
    if let Some(m) = policy.max_memory_bytes {
        // Fail loud, not silent (adversarial-audit P1): if the cgroup memory cap
        // can't be installed (e.g. the memory controller isn't delegated), say so
        // — the agent still has RLIMIT_AS as a fallback address-space cap, so
        // memory is not unbounded, but the stricter cgroup RSS cap did not apply.
        if std::fs::write(format!("{dir}/memory.max"), m.to_string()).is_err() {
            if policy.strict {
                // Strict: a requested cap that can't be installed aborts, rather
                // than silently degrading to RLIMIT_AS only.
                let _ = std::fs::remove_dir(&dir);
                return None;
            }
            eprintln!(
                "tartaros: warning: could not set cgroup memory.max; --max-mem falls \
                 back to RLIMIT_AS only (address space capped, cgroup RSS cap not \
                 applied). Delegate the memory controller for the stricter cap."
            );
        }
    }
    // Capability probe (fail-closed) — ONLY when a hard cap is requested. Creating
    // the directory and writing pids.max can both "succeed" in a container whose
    // cgroup namespace won't actually let a process join a child cgroup (the write
    // to cgroup.procs is accepted but the move never takes effect — observed under
    // Docker without cgroup delegation). There, --max-procs would silently enforce
    // nothing, so we prove membership and warn+degrade if it fails. For a
    // tracking-only cgroup (no caps, used just for cgroup.kill teardown) we skip
    // this probe: a silent membership failure merely falls back to kill(-pgid),
    // and the ~tens-of-ms probe is pure per-launch latency we avoid in the common
    // case (an agent spawns many short commands).
    let has_cap = policy.max_processes.is_some() || policy.max_memory_bytes.is_some();
    if has_cap && !cgroup_membership_works(&dir) {
        let _ = std::fs::remove_dir(&dir);
        warn_cgroup_degraded(policy);
        return None;
    }
    Some(Cgroup { dir })
}

/// Fork a child that does nothing but park briefly, move it into `dir`, and check
/// the cgroup actually accounts it (`pids.current` > 0). Reaps the child. Returns
/// false if the move didn't take effect, so the caller can fail loud.
fn cgroup_membership_works(dir: &str) -> bool {
    let procs = format!("{dir}/cgroup.procs");
    let current = format!("{dir}/pids.current");
    // SAFETY: fork in a single-threaded context (before any spawn); child only
    // makes async-signal-safe-ish syscalls (nanosleep) then _exit.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return false;
    }
    if pid == 0 {
        // Child: park briefly so the parent can observe membership, then exit.
        let ts = libc::timespec { tv_sec: 0, tv_nsec: 10_000_000 };
        unsafe {
            libc::nanosleep(&ts, std::ptr::null_mut());
            libc::_exit(0);
        }
    }
    // Parent: move the child into the cgroup and read back pids.current.
    let moved = std::fs::write(&procs, format!("{pid}\n")).is_ok();
    let accounted = moved
        && std::fs::read_to_string(&current)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(|n| n > 0)
            .unwrap_or(false);
    // Kill and reap the throwaway child; reaping removes it from the cgroup's
    // accounting, leaving `dir` empty and removable / ready for the real child.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
    }
    accounted
}

/// Tear down a cgroup created by [`create_cgroup`]. A cgroup directory can only
/// be removed once empty, so first SIGKILL every member at once via `cgroup.kill`
/// (cgroup v2), then retry `rmdir` briefly while the kernel reaps the members.
/// Leaking the directory is harmless (each run uses a unique name) but untidy.
pub(crate) fn destroy_cgroup(dir: &str) {
    let _ = std::fs::write(format!("{dir}/cgroup.kill"), "1");
    for _ in 0..50 {
        if std::fs::remove_dir(dir).is_ok() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn now_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Is there a usable (writable) cgroup v2 on this host? Read-only probe: try to
/// create and remove a throwaway cgroup. Mirrors `create_cgroup`'s requirement.
pub(crate) fn cgroup_usable() -> bool {
    if !std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        return false;
    }
    let dir = format!("/sys/fs/cgroup/tartaros-probe-{}-{}", std::process::id(), now_nanos());
    if std::fs::create_dir(&dir).is_ok() {
        let _ = std::fs::remove_dir(&dir);
        true
    } else {
        false
    }
}

