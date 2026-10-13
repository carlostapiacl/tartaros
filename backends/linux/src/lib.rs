//! Linux backend — Landlock.
//!
//! Landlock cannot express "allow X but deny X/y", so nono refuses such a
//! policy. TartarOS restructures instead: [`Policy::linux_write_allowlist`] carves
//! the deny out of the allow (grant safe subtrees, exclude the protected
//! branch). This backend turns that allow-list into a Landlock ruleset:
//!   - read + execute everywhere (so ordinary tools run);
//!   - write only under the carved allow-list.
//! A protected path (e.g. a nested `.git/hooks`) has no write-granting rule on
//! it or any ancestor, so writes to it are denied — and because an on-path
//! ancestor like `work/a` is never write-granted, renaming it to relocate the
//! protected path is denied too. That closes the ancestor-rename bypass on
//! Linux the same way the carve does.
//!
//! Enforcement is Linux-only. On other targets this compiles as a fail-closed
//! stub so the workspace still builds during development.

use tartaros_core::{
    Backend, Collector, EffectSink, Policy, PolicyError, RunError, RunOutcome,
};

pub struct LandlockBackend;

impl Backend for LandlockBackend {
    fn name(&self) -> &str {
        "linux-landlock"
    }

    fn validate(&self, policy: &Policy) -> Result<(), PolicyError> {
        if policy.writable_roots.is_empty() {
            return Err(PolicyError { reason: "no writable roots".into() });
        }
        // TartarOS can always express the policy by restructuring (nono rejects).
        let _allow = policy.linux_write_allowlist();
        Ok(())
    }

    fn run(&self, policy: &Policy, command: &[String]) -> Result<RunOutcome, RunError> {
        self.validate(policy).map_err(|e| RunError { reason: e.reason })?;
        if command.is_empty() {
            return Err(RunError { reason: "empty command".into() });
        }
        run_impl(policy, command)
    }
}

impl LandlockBackend {
    /// Spawn the confined command without waiting, so collectors can observe its
    /// process tree by pid while it runs. Linux only.
    #[cfg(target_os = "linux")]
    pub fn spawn(
        &self,
        policy: &Policy,
        command: &[String],
    ) -> Result<std::process::Child, RunError> {
        self.validate(policy).map_err(|e| RunError { reason: e.reason })?;
        if command.is_empty() {
            return Err(RunError { reason: "empty command".into() });
        }
        let mut cmd = confined_command(policy, command, None)?;
        cmd.spawn().map_err(|e| RunError { reason: format!("spawn: {e}") })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn spawn(
        &self,
        _policy: &Policy,
        _command: &[String],
    ) -> Result<std::process::Child, RunError> {
        Err(RunError { reason: "spawn is Linux-only".into() })
    }

    /// Run confined AND observe it with collectors, under the SAME supervisor as
    /// [`Backend::run`] (timeout, resource limits, process-group reaping). Enabling
    /// observation never changes the enforcement guarantees (external review P0).
    #[cfg(target_os = "linux")]
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
        self.validate(policy).map_err(|e| RunError { reason: e.reason })?;
        if command.is_empty() {
            return Err(RunError { reason: "empty command".into() });
        }
        let cg = create_cgroup(policy);
        let procs = cg.as_ref().map(|d| format!("{d}/cgroup.procs"));
        let mut cmd = confined_command(policy, command, procs)?;
        let child = cmd.spawn().map_err(|e| RunError { reason: format!("spawn: {e}") })?;
        let mut cols = make_collectors(child.id());
        let code = supervise(child, policy.timeout, cg.as_deref(), &mut cols, sink);
        if let Some(d) = cg { destroy_cgroup(&d); }
        Ok(RunOutcome { exit_code: code })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn run_observed<F>(
        &self,
        _policy: &Policy,
        _command: &[String],
        _sink: &mut dyn EffectSink,
        _make_collectors: F,
    ) -> Result<RunOutcome, RunError>
    where
        F: FnOnce(u32) -> Vec<Box<dyn Collector>>,
    {
        Err(RunError { reason: "run_observed is Linux-only".into() })
    }
}

#[cfg(not(target_os = "linux"))]
fn run_impl(_policy: &Policy, _command: &[String]) -> Result<RunOutcome, RunError> {
    Err(RunError { reason: "linux-landlock enforcement is only available on Linux".into() })
}

#[cfg(target_os = "linux")]
fn run_impl(policy: &Policy, command: &[String]) -> Result<RunOutcome, RunError> {
    use tartaros_core::VecSink;
    let cg = create_cgroup(policy);
    let procs = cg.as_ref().map(|d| format!("{d}/cgroup.procs"));
    let mut cmd = confined_command(policy, command, procs)?;
    let child = cmd.spawn().map_err(|e| RunError { reason: format!("spawn: {e}") })?;
    let code = supervise(child, policy.timeout, cg.as_deref(), &mut [], &mut VecSink::default());
    if let Some(d) = cg { destroy_cgroup(&d); }
    Ok(RunOutcome { exit_code: code })
}

/// Build a `Command` that applies the Landlock ruleset in the child just before
/// exec. Shared by `run` (waits) and `spawn` (observed).
#[cfg(target_os = "linux")]
fn confined_command(
    policy: &Policy,
    command: &[String],
    cgroup_procs: Option<String>,
) -> Result<std::process::Command, RunError> {
    use landlock::{
        ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, NetPort, PathBeneath, PathFd,
        Ruleset, RulesetAttr, RulesetCreatedAttr,
    };
    use tartaros_core::Network;
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    let err = |m: String| RunError { reason: m };

    // P1-2 mitigation (opt-in), hardened per review P1-A: materialize absent
    // trust-handoff placeholders so Landlock (inode-based) can carve them. This
    // FAILS CLOSED (never runs with partial protection), refuses to act through a
    // symlinked ancestor (anti-TOCTOU), creates with O_EXCL, and verifies.
    if policy.materialize_absent_handoff {
        use std::os::unix::fs::PermissionsExt;
        for p in policy.handoff_placeholders() {
            if has_symlink_component(&p) {
                return Err(err(format!(
                    "materialize: refusing to act through a symlinked path: {}",
                    p.display()
                )));
            }
            let parent = p
                .parent()
                .ok_or_else(|| err(format!("materialize: no parent for {}", p.display())))?;
            std::fs::create_dir_all(parent)
                .map_err(|e| err(format!("materialize mkdir {}: {e}", parent.display())))?;

            let is_dir = p.file_name().map(|n| n == "workflows").unwrap_or(false);
            if is_dir {
                std::fs::create_dir_all(&p)
                    .map_err(|e| err(format!("materialize mkdir {}: {e}", p.display())))?;
            } else {
                // O_CREAT|O_EXCL: no clobber, no check-then-write race.
                match std::fs::OpenOptions::new().write(true).create_new(true).open(&p) {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(err(format!("materialize create {}: {e}", p.display()))),
                }
            }
            let mut perm = std::fs::symlink_metadata(&p)
                .map_err(|e| err(format!("materialize stat {}: {e}", p.display())))?
                .permissions();
            perm.set_mode(0o444);
            std::fs::set_permissions(&p, perm)
                .map_err(|e| err(format!("materialize chmod {}: {e}", p.display())))?;
            // verify
            if !p.exists() {
                return Err(err(format!("materialize: {} missing after create", p.display())));
            }
        }
    }

    // Request up to ABI v5 (TCP port rules arrived in v4, kernel 6.7); BestEffort
    // degrades on older kernels. NOTE: on a kernel without Landlock network
    // support, network rules are silently dropped — net confinement needs
    // kernel >= 6.7. Filesystem confinement still applies.
    let abi = ABI::V5;
    let read_only = AccessFs::from_read(abi);
    let all = AccessFs::from_all(abi);
    // Write rules must NOT grant read: Landlock unions rule permissions, so a
    // write grant that included read would re-open a read-denied secret located
    // inside a writable root (external review P0). Read is governed solely by the
    // read carve; writes grant write rights only.
    let write_only = all & !read_only;

    // Restrict the network unless the policy explicitly opened it.
    let restrict_net = !matches!(policy.network, Some(Network::Allowed));

    // FAIL CLOSED (external review P0-2): never run under-confined. If the kernel
    // lacks a capability the policy requires, abort instead of silently degrading.
    if !landlock_fs_supported() {
        return Err(err(
            "Landlock filesystem confinement unavailable (needs Linux >= 5.13); refusing to run unconfined".into(),
        ));
    }
    if restrict_net && !landlock_net_supported() {
        return Err(err(
            "network confinement requested but Landlock network rules unavailable (needs Linux >= 6.7); refusing to run with unrestricted network".into(),
        ));
    }

    let mut builder = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(all)
        .map_err(|e| err(format!("handle_access fs: {e}")))?;
    if restrict_net {
        builder = builder
            .handle_access(AccessNet::ConnectTcp | AccessNet::BindTcp)
            .map_err(|e| err(format!("handle_access net: {e}")))?;
    }
    let mut ruleset = builder.create().map_err(|e| err(format!("create ruleset: {e}")))?;

    // Read + execute everywhere EXCEPT the secret dirs (carved out of /), so the
    // command and its libraries load but it cannot read `~/.ssh` etc.
    for p in policy.linux_read_allowlist() {
        let fd = match PathFd::new(&p) {
            Ok(fd) => fd,
            Err(_) => continue,
        };
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, read_only))
            .map_err(|e| err(format!("add read rule {}: {e}", p.display())))?;
    }

    // Write only under the carved allow-list.
    for p in policy.linux_write_allowlist() {
        let fd = match PathFd::new(&p) {
            Ok(fd) => fd,
            Err(_) => continue, // a path that vanished between carve and open: skip
        };
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, write_only))
            .map_err(|e| err(format!("add write rule {}: {e}", p.display())))?;
    }

    // Writable /dev (the directory, so Landlock covers its hierarchy) — tools
    // need /dev/null, /dev/tty, etc. Not secrets, and a non-root process can't
    // harm raw devices. Mirrors the macOS backend's /dev allow. A rule on a
    // special file (e.g. /dev/stdout, a symlinked pipe) fails, so we grant the
    // directory, not each node.
    let dev_fd = PathFd::new("/dev").map_err(|e| err(format!("open /dev: {e}")))?;
    ruleset = ruleset
        .add_rule(PathBeneath::new(dev_fd, write_only))
        .map_err(|e| err(format!("add /dev rule: {e}")))?;

    // Network: allow TCP connect/bind only on the granted ports. Landlock net is
    // port-based (not host-based): a granted port is reachable on any host, so
    // loopback-vs-external is left to the proxy layer. With no granted ports and
    // restriction on, all TCP connect/bind is denied.
    if restrict_net {
        for port in &policy.local_ports {
            ruleset = ruleset
                .add_rule(NetPort::new(*port, AccessNet::ConnectTcp))
                .map_err(|e| err(format!("add connect port {port}: {e}")))?;
            ruleset = ruleset
                .add_rule(NetPort::new(*port, AccessNet::BindTcp))
                .map_err(|e| err(format!("add bind port {port}: {e}")))?;
        }
    }

    // Apply in the child, just before exec, so only the sandboxed process is
    // restricted. The ruleset fd was built here in the parent.
    let mut created = Some(ruleset);
    let max_memory = policy.max_memory_bytes;
    let max_processes = policy.max_processes;
    let max_cpu = policy.max_cpu_secs;
    let deny_unix = policy.deny_unix_sockets;
    let isolate_pids = policy.isolate_pids;
    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]);
    unsafe {
        cmd.pre_exec(move || {
            // Own process group so the supervisor can signal the whole tree.
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Join the cgroup BEFORE any PID-namespace unshare: inside a new PID
            // namespace getpid() returns the namespaced pid (1), which is not what
            // cgroup.procs expects. Joining here (host pid) and letting the agent
            // inherit membership keeps the cgroup caps and cgroup.kill teardown
            // working across the namespace boundary.
            if let Some(path) = &cgroup_procs {
                let pid = format!("{}\n", libc::getpid());
                let cpath = std::ffi::CString::new(path.as_str()).unwrap();
                let fd = libc::open(cpath.as_ptr(), libc::O_WRONLY);
                if fd >= 0 {
                    let _ = libc::write(fd, pid.as_ptr() as *const _, pid.len());
                    libc::close(fd);
                }
            }
            // Private PID + mount namespace (opt-in). Must happen before the
            // Landlock lockdown (mounting /proc needs CAP_SYS_ADMIN and an
            // unrestricted mount tree). Fails closed. See enter_pid_namespace.
            if isolate_pids {
                enter_pid_namespace()?;
            }
            // Resource limits (P1-B) before dropping into the sandbox.
            set_rlimit(libc::RLIMIT_AS, max_memory)?;
            set_rlimit(libc::RLIMIT_NPROC, max_processes)?;
            set_rlimit(libc::RLIMIT_CPU, max_cpu)?;
            // Deny AF_UNIX sockets (IPC-1) via seccomp, if the policy asked.
            if deny_unix {
                apply_deny_af_unix()?;
            }
            // Landlock.
            created
                .take()
                .expect("restrict_self called once")
                .restrict_self()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
            // Close inherited non-stdio fds just before exec (defense-in-depth):
            // an fd opened by the parent bypasses path-based confinement because
            // the open already happened. Done last so the ruleset fd was still live.
            close_inherited_fds();
            Ok(())
        });
    }
    Ok(cmd)
}

/// Put the agent in a private PID + mount namespace so it sees only its own
/// process subtree. Called from `pre_exec` (child, before the Landlock lockdown)
/// and after the cgroup join. On return the caller continues as PID 1 of a new
/// PID namespace with a fresh `/proc`; it never returns in the parent, which
/// becomes a thin init that reaps the agent and propagates its exit status.
///
/// Fails closed: if any step is denied (e.g. no CAP_SYS_ADMIN inside an
/// undelegated container), it returns an error and the launch is aborted rather
/// than running without the requested isolation.
#[cfg(target_os = "linux")]
unsafe fn enter_pid_namespace() -> std::io::Result<()> {
    // New mount + PID namespace. CLONE_NEWPID takes effect on the next fork:
    // this process stays in the old PID ns and its first child is PID 1 of the
    // new one.
    if libc::unshare(libc::CLONE_NEWNS | libc::CLONE_NEWPID) != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Make the mount tree private so our fresh /proc does not propagate to (or
    // from) the host mount namespace.
    let root = c"/";
    if libc::mount(
        std::ptr::null(),
        root.as_ptr(),
        std::ptr::null(),
        libc::MS_REC | libc::MS_PRIVATE,
        std::ptr::null(),
    ) != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let pid = libc::fork();
    if pid < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if pid > 0 {
        // Init shim (stays in the old PID ns): wait for the agent and exit with
        // its status, so the supervisor sees the agent's real exit code.
        //
        // Close every inherited non-stdio fd first. std::process keeps a
        // CLOEXEC exec-status pipe; the agent (G) closes its copy when it
        // execs, but this shim would hold its copy open for the whole run,
        // so Command::spawn() in the parent would BLOCK reading that pipe until
        // the run ends — the supervisor (and its timeout) would never start.
        // Closing here releases the pipe the moment the agent execs.
        close_inherited_fds();
        let mut status: libc::c_int = 0;
        while libc::waitpid(pid, &mut status, 0) < 0 {
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                libc::_exit(1);
            }
        }
        let code = if (status & 0x7f) == 0 {
            (status >> 8) & 0xff // WEXITSTATUS
        } else {
            128 + (status & 0x7f) // 128 + WTERMSIG
        };
        libc::_exit(code);
    }
    // Agent (PID 1 of the new namespace): mount a fresh procfs so /proc reflects
    // this namespace (only our own processes), not the host's.
    let proc_src = c"proc";
    let proc_tgt = c"/proc";
    if libc::mount(
        proc_src.as_ptr(),
        proc_tgt.as_ptr(),
        proc_src.as_ptr(),
        0,
        std::ptr::null(),
    ) != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Close every inherited fd >= 3 (keep stdio) just before exec. `close_range`
/// (Linux 5.9+) is a single async-signal-safe syscall; fall back to a bounded
/// loop if it is unavailable.
#[cfg(target_os = "linux")]
unsafe fn close_inherited_fds() {
    let rc = libc::syscall(libc::SYS_close_range, 3u64, u32::MAX as u64, 0u64);
    if rc != 0 {
        for fd in 3..1024 {
            libc::close(fd);
        }
    }
}

/// Deny creating `AF_UNIX` sockets via seccomp (IPC-1). Everything else is
/// allowed, so TCP (AF_INET), files, etc. keep working. Requires no-new-privs,
/// which we set here (Landlock sets it too, but seccomp is applied first).
#[cfg(target_os = "linux")]
fn apply_deny_af_unix() -> std::io::Result<()> {
    use seccompiler::{
        apply_filter, BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
        SeccompFilter, SeccompRule,
    };
    let to_io = |m: String| std::io::Error::new(std::io::ErrorKind::Other, m);

    // no_new_privs is required to install a seccomp filter unprivileged.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }

    // Match socket(domain == AF_UNIX, ..) and return EACCES; allow all else.
    let cond = SeccompCondition::new(
        0,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::Eq,
        libc::AF_UNIX as u64,
    )
    .map_err(|e| to_io(format!("seccomp cond: {e}")))?;
    let rule = SeccompRule::new(vec![cond]).map_err(|e| to_io(format!("seccomp rule: {e}")))?;
    let mut map = std::collections::BTreeMap::new();
    map.insert(libc::SYS_socket, vec![rule]);
    let filter = SeccompFilter::new(
        map,
        SeccompAction::Allow,                            // default: allow
        SeccompAction::Errno(libc::EACCES as u32),       // matched: deny
        std::env::consts::ARCH.try_into().map_err(|e| to_io(format!("seccomp arch: {e}")))?,
    )
    .map_err(|e| to_io(format!("seccomp filter: {e}")))?;
    let prog: BpfProgram = filter.try_into().map_err(|e| to_io(format!("seccomp compile: {e}")))?;
    apply_filter(&prog).map_err(|e| to_io(format!("seccomp apply: {e}")))?;
    Ok(())
}

/// Create a cgroup v2 with the policy's pid/memory caps, if the cgroup fs is
/// writable (needs a delegated/privileged cgroup). Returns the cgroup dir, whose
/// `cgroup.procs` the child writes its pid into. Guaranteed regardless of uid/caps
/// — unlike RLIMIT_NPROC, which root bypasses (finding RES-1). Best-effort: on a
/// read-only cgroup fs it returns None and we fall back to setrlimit.
#[cfg(target_os = "linux")]
/// Warn (once per run) that a requested resource limit could not be enforced via
/// cgroups and has degraded to RLIMIT. `--max-procs` without a cgroup falls back
/// to RLIMIT_NPROC, which a process running as root (CAP_SYS_RESOURCE) can raise
/// and thus bypass (RES-1). Fail-loud, not fail-silent.
#[cfg(target_os = "linux")]
fn warn_cgroup_degraded(policy: &Policy) {
    if policy.max_processes.is_some() {
        eprintln!(
            "tartaros: warning: cgroup v2 unavailable; --max-procs degraded to \
             RLIMIT_NPROC (best-effort, bypassable by root). Run on a cgroup-v2 host \
             with write access to /sys/fs/cgroup for a hard process cap."
        );
    }
}

#[cfg(target_os = "linux")]
fn create_cgroup(policy: &Policy) -> Option<String> {
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
        let _ = std::fs::write(format!("{dir}/memory.max"), m.to_string());
    }
    // Capability probe (fail-closed): creating the directory and writing pids.max
    // can both "succeed" in a container whose cgroup namespace won't actually let
    // a process join a child cgroup (the write to cgroup.procs is accepted but the
    // move never takes effect — observed under Docker without cgroup delegation).
    // There, --max-procs would silently enforce nothing. Prove membership works by
    // moving a throwaway child in and confirming pids.current rose; if not, discard
    // the cgroup and warn that the limit degraded to RLIMIT.
    if !cgroup_membership_works(&dir) {
        let _ = std::fs::remove_dir(&dir);
        warn_cgroup_degraded(policy);
        return None;
    }
    Some(dir)
}

/// Fork a child that does nothing but park briefly, move it into `dir`, and check
/// the cgroup actually accounts it (`pids.current` > 0). Reaps the child. Returns
/// false if the move didn't take effect, so the caller can fail loud.
#[cfg(target_os = "linux")]
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
        let ts = libc::timespec { tv_sec: 0, tv_nsec: 30_000_000 };
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
#[cfg(target_os = "linux")]
fn destroy_cgroup(dir: &str) {
    let _ = std::fs::write(format!("{dir}/cgroup.kill"), "1");
    for _ in 0..50 {
        if std::fs::remove_dir(dir).is_ok() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[cfg(target_os = "linux")]
fn now_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Apply one `setrlimit` (cur=max=limit) when a limit is set. Returns an io error
/// so a failure aborts the launch (fail closed).
#[cfg(target_os = "linux")]
fn set_rlimit(resource: libc::__rlimit_resource_t, limit: Option<u64>) -> std::io::Result<()> {
    if let Some(v) = limit {
        let rl = libc::rlimit { rlim_cur: v as libc::rlim_t, rlim_max: v as libc::rlim_t };
        if unsafe { libc::setrlimit(resource, &rl) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Supervise a confined child (P1-B): enforce the wall-clock timeout, then reap
/// the whole process group so no descendant is left behind.
#[cfg(target_os = "linux")]
fn supervise(
    mut child: std::process::Child,
    timeout: Option<std::time::Duration>,
    cgroup_dir: Option<&str>,
    collectors: &mut [Box<dyn Collector>],
    sink: &mut dyn EffectSink,
) -> i32 {
    use std::time::{Duration, Instant};
    let pid = child.id() as i32;
    let start = Instant::now();
    let kill_group = |sig: i32| unsafe { libc::kill(-pid, sig); };
    // Kill the whole run. When a cgroup exists, `cgroup.kill` SIGKILLs every
    // member atomically regardless of process group or PID namespace — essential
    // when --isolate-pids makes the agent PID 1 of its namespace, which is immune
    // to signals (even from an ancestor) that `kill(-pgid)` relies on. The
    // process-group kill stays as a fallback for the no-cgroup path.
    let kill_all = |sig: i32| {
        if let Some(d) = cgroup_dir {
            if sig == libc::SIGKILL {
                let _ = std::fs::write(format!("{d}/cgroup.kill"), "1");
            }
        }
        kill_group(sig);
    };
    loop {
        // Poll collectors in the same loop (no-op when there are none), so
        // observation never alters the supervision/timeout behaviour.
        for c in collectors.iter_mut() {
            c.poll(sink);
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                for c in collectors.iter_mut() {
                    c.poll(sink);
                }
                kill_all(libc::SIGKILL);
                return exit_code_of(status);
            }
            Ok(None) => {
                if let Some(t) = timeout {
                    if start.elapsed() >= t {
                        kill_all(libc::SIGTERM);
                        std::thread::sleep(Duration::from_millis(500));
                        kill_all(libc::SIGKILL);
                        let _ = child.wait();
                        kill_all(libc::SIGKILL);
                        return 124; // timed out
                    }
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return -1,
        }
    }
}

#[cfg(target_os = "linux")]
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

/// True if any EXISTING component along `p` is a symlink (P1-A: never
/// materialize through a symlinked ancestor — avoids escaping the workspace or a
/// TOCTOU swap).
#[cfg(target_os = "linux")]
fn has_symlink_component(p: &std::path::Path) -> bool {
    let mut cur = std::path::PathBuf::new();
    for comp in p.components() {
        cur.push(comp);
        if let Ok(m) = std::fs::symlink_metadata(&cur) {
            if m.file_type().is_symlink() {
                return true;
            }
        }
    }
    false
}

/// Probe (fail-closed, P0-2): can this kernel enforce Landlock filesystem rules?
/// Builds a ruleset with HardRequirement — it errors if the capability is absent.
/// Creates no restriction (never calls restrict_self); the fd is dropped.
#[cfg(target_os = "linux")]
fn landlock_fs_supported() -> bool {
    use landlock::{ABI, Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr};
    Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(ABI::V1))
        .and_then(|r| r.create())
        .is_ok()
}

/// Probe (fail-closed, P0-2): can this kernel enforce Landlock TCP network rules
/// (ABI v4, Linux >= 6.7)?
#[cfg(target_os = "linux")]
fn landlock_net_supported() -> bool {
    use landlock::{AccessNet, CompatLevel, Compatible, Ruleset, RulesetAttr};
    Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessNet::ConnectTcp | AccessNet::BindTcp)
        .and_then(|r| r.create())
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tartaros_core::Policy;
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
