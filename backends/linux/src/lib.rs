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
use std::path::PathBuf;

// Per-mechanism modules (linux-only), kept apart so each can be read and tested
// on its own. The seccomp filters live here; cgroup/namespace/landlock helpers
// remain inline in this file for now.
#[cfg(target_os = "linux")]
mod seccomp;
#[cfg(target_os = "linux")]
mod namespace;
#[cfg(target_os = "linux")]
mod cgroup;
#[cfg(target_os = "linux")]
mod landlock_probe;

pub struct LandlockBackend;

impl Backend for LandlockBackend {
    fn name(&self) -> &str {
        "linux-landlock"
    }

    fn validate(&self, policy: &Policy) -> Result<(), PolicyError> {
        if policy.writable_roots.is_empty() {
            return Err(PolicyError { reason: "no writable roots".into() });
        }
        // AF_UNIX cannot be filtered by path on the seccomp backend (it is
        // all-or-nothing). Honouring an allow-one-socket request by ignoring it
        // would silently widen the sandbox, so refuse — the caller uses
        // --deny-unix for all-or-nothing, or runs on macOS for per-path allow.
        if !policy.allow_unix_socket_paths.is_empty() {
            return Err(PolicyError {
                reason: "allow_unix_socket_paths is unsupported on Linux: the seccomp backend \
                         filters AF_UNIX all-or-nothing, not per path. Use deny_unix_sockets for \
                         all-or-nothing, or the macOS (Seatbelt) backend for per-path allow."
                    .into(),
            });
        }
        if !policy.glob_denies.is_empty() {
            return Err(PolicyError {
                reason: "glob_denies is unsupported on Linux: Landlock matches by inode and \
                         cannot enforce a single-* path glob. Use concrete paths, or run the \
                         macOS (Seatbelt) backend, which compiles these to anchored regexes."
                    .into(),
            });
        }
        if !policy.allow_mach_lookup.is_empty() || !policy.allow_mach_register.is_empty() {
            return Err(PolicyError {
                reason: "allow_mach_lookup/allow_mach_register are macOS-only: Mach is a Darwin \
                         IPC primitive with no Linux equivalent. Headless browsers that need Mach \
                         rendezvous run under the macOS (Seatbelt) backend."
                    .into(),
            });
        }
        if policy.browser {
            return Err(PolicyError {
                reason: "--browser (the headless-browser Seatbelt grants: POSIX shm/sem, IOKit \
                         user clients, kern.proc.pid/tcsm sysctls) is a macOS concept with no \
                         Linux equivalent. Run browser roles under the macOS (Seatbelt) backend."
                    .into(),
            });
        }
        // TartarOS can always express the rest of the policy by restructuring.
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
        let cg = match cgroup::create_cgroup(policy) {
            Ok(c) => c,
            // Strict + a cgroup present but a requested cap could not be installed
            // (partial delegation): abort with the precise cause (ADV-04).
            Err(reason) => return Err(RunError { reason: format!("strict mode: {reason}; refusing to run") }),
        };
        if policy.strict && cg.is_none() && (policy.max_processes.is_some() || policy.max_memory_bytes.is_some()) {
            return Err(RunError { reason: "strict mode: requested resource caps cannot be guaranteed on this host (no usable cgroup v2); refusing to run".into() });
        }
        let procs = cg.as_ref().map(|c| c.procs_path());
        // If confined_command or spawn fails here, `cg` drops and tears down the
        // cgroup — no explicit cleanup, no leak on the error paths.
        let mut cmd = confined_command(policy, command, procs)?;
        let child = cmd.spawn().map_err(|e| RunError { reason: format!("spawn: {e}") })?;
        let mut cols = make_collectors(child.id());
        let code = supervise(child, policy.timeout, cg.as_ref().map(|c| c.dir()), &mut cols, sink);
        Ok(RunOutcome { exit_code: code }) // cg drops here -> cgroup torn down
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
    let cg = match cgroup::create_cgroup(policy) {
        Ok(c) => c,
        Err(reason) => return Err(RunError { reason: format!("strict mode: {reason}; refusing to run") }),
    };
    if policy.strict && cg.is_none() && (policy.max_processes.is_some() || policy.max_memory_bytes.is_some()) {
        return Err(RunError { reason: "strict mode: requested resource caps cannot be guaranteed on this host (no usable cgroup v2); refusing to run".into() });
    }
    let procs = cg.as_ref().map(|c| c.procs_path());
    // `cg` drops on every exit path (incl. the `?` below) -> cgroup torn down.
    let mut cmd = confined_command(policy, command, procs)?;
    let child = cmd.spawn().map_err(|e| RunError { reason: format!("spawn: {e}") })?;
    let code = supervise(child, policy.timeout, cg.as_ref().map(|c| c.dir()), &mut [], &mut VecSink::default());
    Ok(RunOutcome { exit_code: code })
}

/// Build a `Command` that applies the Landlock ruleset in the child just before
/// exec. Shared by `run` (waits) and `spawn` (observed).
#[cfg(target_os = "linux")]
/// The EXISTING trust-handoff + explicit-write-deny paths we would protect with
/// read-only bind mounts, or empty when the bind-mount strategy is unavailable
/// (no mount privilege) or unneeded (nothing to protect). Non-empty means the
/// workspace is granted wholesale and these are bound read-only (option B:
/// existing paths only — the working tree is never materialized/touched).
#[cfg(target_os = "linux")]
fn robind_targets(policy: &Policy) -> Vec<PathBuf> {
    // Need a mount namespace: real root has it; otherwise a user namespace can
    // grant it (unless the host blocks unprivileged userns, e.g. AppArmor). The
    // probe forks, so only call it when there is actually something to protect.
    let mut paths: Vec<PathBuf> = Vec::new();
    for r in policy.trust_handoff_rules() {
        paths.push(r.path);
    }
    for r in policy.fs_rules.iter().filter(|r| r.access == tartaros_core::Access::Deny) {
        paths.push(r.path.clone());
    }
    paths.retain(|p| p.exists());
    paths.sort();
    paths.dedup();
    // Nothing to protect, or no way to create a mount namespace on this host: fall
    // back to the Landlock carve (the probe forks, so gate it on paths first).
    if paths.is_empty() || !namespace::mount_ns_capable() {
        return Vec::new();
    }
    paths
}

/// Would this policy be enforced with the read-only bind-mount strategy (whole
/// workspace writable + handoff bound read-only), rather than the write carve?
/// Used by the CLI to decide whether to warn about the carve's create-at-root
/// limitation.
#[cfg(target_os = "linux")]
pub fn uses_bind_mounts(policy: &Policy) -> bool {
    !robind_targets(policy).is_empty()
}

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

    // Fail closed with an actionable diagnostic. --isolate-pids / --isolate-net
    // need a private PID/mount/net namespace, which a non-root user can only create
    // inside a user namespace. If the host forbids unprivileged user namespaces
    // (hardened Ubuntu/Debian/Arch, or a container without CAP_SYS_ADMIN) we REFUSE
    // rather than run without the isolation the caller asked for — never a silent
    // downgrade. Root never hits this. (The bind-mount strategy degrades to the
    // Landlock carve in the same case, by design — option B — so it is not refused.)
    if (policy.isolate_pids || policy.isolate_network)
        && unsafe { libc::geteuid() } != 0
        && !namespace::mount_ns_capable()
    {
        return Err(err(format!(
            "refusing to run: --isolate-{} needs a private namespace, but {}",
            if policy.isolate_pids { "pids" } else { "net" },
            namespace::userns_blocker_hint()
        )));
    }

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
    // Also never grant device-node creation: with MakeBlock/MakeChar on a writable
    // /dev a root agent could `mknod` a block device and read the raw disk,
    // bypassing the path-based secret protection entirely (adversarial review #3).
    // Agents never need to create device nodes; mknod is also denied via seccomp.
    let write_only = all & !read_only & !AccessFs::MakeBlock & !AccessFs::MakeChar;

    // Restrict the network unless the policy explicitly opened it.
    let restrict_net = !matches!(policy.network, Some(Network::Allowed));

    // FAIL CLOSED (external review P0-2): never run under-confined. If the kernel
    // lacks a capability the policy requires, abort instead of silently degrading.
    if !landlock_probe::landlock_fs_supported() {
        return Err(err(
            "Landlock filesystem confinement unavailable (needs Linux >= 5.13); refusing to run unconfined".into(),
        ));
    }
    if restrict_net && !landlock_probe::landlock_net_supported() {
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

    // Trust-handoff enforcement strategy. Landlock cannot allow "write X but deny
    // X/y", so the carve grants each safe subtree and NEVER the parent of a deny —
    // which blocks creating NEW entries directly at a repo root (a deny lives below
    // in .git/hooks). When we can create a mount namespace (CAP_SYS_ADMIN, i.e.
    // running as root / in a container), we instead grant the WHOLE workspace
    // writable and protect each EXISTING handoff path with a read-only bind mount
    // at the VFS layer — the bubblewrap/sandbox-runtime approach — so new files at
    // the root work while the handoff stays unwritable. Mounts live only in the
    // agent's private mount namespace and leave no trace in the real tree (option
    // B: existing paths only; absent ones are not materialized). Without the
    // privilege we fall back to the carve (same guarantees as before).
    let robind_paths = robind_targets(policy);
    let use_bind_mounts = !robind_paths.is_empty();

    // Write grant: whole roots when bind mounts protect the handoff; else the carve.
    let write_grants: Vec<PathBuf> =
        if use_bind_mounts { policy.writable_roots.clone() } else { policy.linux_write_allowlist() };
    for p in &write_grants {
        let fd = match PathFd::new(p) {
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
    let harden_syscalls = policy.harden_syscalls;
    let isolate_pids = policy.isolate_pids;
    let isolate_network = policy.isolate_network;
    // Compile the seccomp BPF programs HERE in the parent (allocation is fine),
    // not in pre_exec — building a BPF program after fork could deadlock a child of
    // a multithreaded parent (broker/collector threads) on the malloc lock (review
    // #7). The child only applies them (prctl + apply_filter, no allocation).
    let seccomp_progs = seccomp::compile_all(deny_unix, harden_syscalls, restrict_net)
        .map_err(|e| err(format!("seccomp compile: {e}")))?;
    // Read-only bind-mount targets (built here in the parent; the pre_exec closure
    // must not allocate/stat). Empty unless we chose the bind-mount strategy.
    let robind_cstrings: Vec<std::ffi::CString> = {
        use std::os::unix::ffi::OsStrExt;
        robind_paths
            .iter()
            .filter_map(|p| std::ffi::CString::new(p.as_os_str().as_bytes()).ok())
            .collect()
    };
    // Pre-build (in the parent) everything pre_exec would otherwise allocate after
    // the fork (review #7): the cgroup.procs path as a CString, and the user-ns
    // uid/gid maps (euid/egid are preserved across fork).
    let cgroup_procs_c: Option<std::ffi::CString> =
        cgroup_procs.as_ref().and_then(|p| std::ffi::CString::new(p.as_str()).ok());
    let (userns_uid_map, userns_gid_map) = namespace::uid_gid_maps();
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
            if let Some(cpath) = &cgroup_procs_c {
                let mut buf = [0u8; 16];
                let pid = namespace::fmt_pid(&mut buf, libc::getpid());
                let fd = libc::open(cpath.as_ptr(), libc::O_WRONLY);
                if fd >= 0 {
                    let _ = libc::write(fd, pid.as_ptr() as *const _, pid.len());
                    libc::close(fd);
                }
            }
            // Private namespaces and bind mounts (all opt-in) need CAP_SYS_ADMIN.
            // A non-root user gains it by entering a USER namespace first — the
            // bubblewrap approach — which then lets the PID/mount/net unshares and
            // the bind-mount remounts all succeed unprivileged wherever the host
            // permits it. We enter it ONCE here so --isolate-pids and the bind
            // mounts share the same userns (entering it twice would nest and break
            // the uid maps). Real root already has CAP_SYS_ADMIN and skips it. The
            // parent refused up front if isolation was requested on a host that
            // forbids the userns, so reaching here means these steps will work.
            // Must precede the Landlock lockdown (mounting /proc, loopback, and the
            // binds need CAP_SYS_ADMIN and an unrestricted mount tree). Fails closed.
            let not_root = libc::geteuid() != 0;
            let need_userns =
                not_root && (isolate_pids || isolate_network || !robind_cstrings.is_empty());
            if need_userns {
                namespace::enter_user_namespace(&userns_uid_map, &userns_gid_map)?;
            }
            if isolate_pids || isolate_network {
                namespace::enter_namespaces(isolate_pids, isolate_network)?;
            }
            // Read-only bind mounts for the trust-handoff set (so the workspace can
            // be granted writable without the handoff being writable). need_unshare:
            // isolate_pids already made a mount namespace; otherwise create one here
            // (we hold CAP_SYS_ADMIN now, root or via the userns above). Fails closed
            // — a mount error aborts before the workspace is ever exposed writable.
            if !robind_cstrings.is_empty() {
                namespace::setup_ro_binds(&robind_cstrings, !isolate_pids)?;
            }
            // Kill-switch (supervisor loss): die if our parent dies, even on a
            // SIGKILL of the supervisor that never runs destroy_cgroup.
            //   - With --isolate-pids this is a COMPLETE tree-kill: the parent is
            //     the init shim (which carries the same request against the
            //     supervisor), and the agent is PID 1 of its namespace, so the
            //     chain supervisor→shim→agent collapses and the whole namespace —
            //     every descendant — is torn down. Nothing outlives the box.
            //   - Without it, PR_SET_PDEATHSIG reaps only THIS (direct child)
            //     process; a grandchild the agent forked can be reparented to init
            //     and survive. The full guarantee needs the PID namespace (which
            //     the hostile-code / multi-tenant profiles enable by default).
            namespace::set_pdeathsig_kill();
            // Resource limits (P1-B) before dropping into the sandbox.
            set_rlimit(libc::RLIMIT_AS as libc::c_int, max_memory)?;
            set_rlimit(libc::RLIMIT_NPROC as libc::c_int, max_processes)?;
            set_rlimit(libc::RLIMIT_CPU as libc::c_int, max_cpu)?;
            // Bound open file descriptors: the inherited soft limit (often 1024) is
            // raisable by the agent up to the hard limit (often ~1M), which would
            // let it exhaust kernel fd-table memory. Cap the HARD limit so it can't
            // be raised past a generous ceiling (65536 >> any real toolchain needs),
            // keeping the soft limit usable. async-signal-safe (getrlimit/setrlimit).
            {
                const MAX_NOFILE: libc::rlim_t = 65536;
                let mut rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
                if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) == 0 {
                    let hard = rl.rlim_max.min(MAX_NOFILE);
                    let soft = rl.rlim_cur.min(hard);
                    let newrl = libc::rlimit { rlim_cur: soft, rlim_max: hard };
                    let _ = libc::setrlimit(libc::RLIMIT_NOFILE, &newrl);
                }
            }
            // Apply the seccomp filters compiled in the parent (AF_UNIX deny, the
            // syscall-hardening set, the UDP/ICMP/raw egress close, and io_uring) —
            // pre_exec only applies, never compiles (no allocation after fork,
            // review #7). The filters stack; all were selected by compile_all.
            seccomp::apply_all(&seccomp_progs)?;
            // Drop all capabilities when running as real root (review #3), after the
            // privileged setup (cgroup join, namespaces, bind mounts) has run and
            // before the agent execs. A uid-0 agent otherwise keeps CAP_SYS_MODULE,
            // CAP_SYS_RAWIO, CAP_SYS_PTRACE, etc. No-op for a non-root euid.
            namespace::drop_all_capabilities()?;
            // Landlock.
            created
                .take()
                .expect("restrict_self called once")
                .restrict_self()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
            // Close inherited non-stdio fds just before exec (defense-in-depth):
            // an fd opened by the parent bypasses path-based confinement because
            // the open already happened. Done last so the ruleset fd was still live.
            namespace::cloexec_inherited_fds();
            Ok(())
        });
    }
    Ok(cmd)
}

/// Apply one `setrlimit` (cur=max=limit) when a limit is set. Returns an io error
/// so a failure aborts the launch (fail closed).
#[cfg(target_os = "linux")]
// `resource` is a plain c_int so the call sites are portable: glibc types
// RLIMIT_* as `__rlimit_resource_t` (absent on musl), musl as c_int. We cast to
// whatever `setrlimit` expects with `as _`.
fn set_rlimit(resource: libc::c_int, limit: Option<u64>) -> std::io::Result<()> {
    if let Some(v) = limit {
        let rl = libc::rlimit { rlim_cur: v as libc::rlim_t, rlim_max: v as libc::rlim_t };
        if unsafe { libc::setrlimit(resource as _, &rl) } != 0 {
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
    // Adaptive poll: short commands (the common agent case) finish in ~1ms, so
    // start tight and back off to 50ms for long runs — this removes a fixed ~50ms
    // per-launch latency without busy-spinning a long process (or over-polling
    // the collectors). Correctness (timeout, teardown) is independent of cadence.
    let mut poll_ms = 1u64;
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
                std::thread::sleep(Duration::from_millis(poll_ms));
                poll_ms = (poll_ms * 2).min(50);
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

/// Does THIS host block `run` for this policy? Returns the reason `run` would
/// refuse (fail-closed), or None if it would proceed. `explain` calls this and
/// exits non-zero wherever `run` would refuse, so an external audit
/// never shows a green ✓ on a host that cannot actually enforce the policy.
#[cfg(target_os = "linux")]
pub fn host_blocks_run(policy: &Policy) -> Option<String> {
    use tartaros_core::Network;
    if !landlock_probe::landlock_fs_supported() {
        return Some("Landlock filesystem confinement unavailable (needs Linux >= 5.13); run refuses to run unconfined".into());
    }
    let restrict_net = !matches!(policy.network, Some(Network::Allowed));
    if restrict_net && !landlock_probe::landlock_net_supported() {
        return Some("network confinement requested but Landlock network rules unavailable (needs Linux >= 6.7); run refuses".into());
    }
    if (policy.isolate_pids || policy.isolate_network)
        && unsafe { libc::geteuid() } != 0
        && !namespace::mount_ns_capable()
    {
        let which = if policy.isolate_pids { "pids" } else { "net" };
        return Some(format!(
            "--isolate-{which} needs a private namespace, but {}",
            namespace::userns_blocker_hint()
        ));
    }
    if policy.strict
        && !cgroup::cgroup_usable()
        && (policy.max_processes.is_some() || policy.max_memory_bytes.is_some())
    {
        return Some("strict mode: requested resource caps cannot be guaranteed on this host (no usable cgroup v2); run refuses".into());
    }
    None
}

/// Resolve what this policy will ACTUALLY enforce on THIS host, so a user can
/// verify guarantees before running instead of relying on stderr warnings
/// (adversarial-audit: queryable `AppliedPolicy`). Each line is
/// `<knob>: <GUARANTEED|BEST-EFFORT|PARTIAL|UNAVAILABLE> (<how>)`.
#[cfg(target_os = "linux")]
pub fn enforcement_report(policy: &Policy) -> Vec<String> {
    use tartaros_core::Network;
    let mut out = Vec::new();
    out.push(if landlock_probe::landlock_fs_supported() {
        "filesystem / trust-handoff: GUARANTEED (Landlock)".into()
    } else {
        "filesystem / trust-handoff: UNAVAILABLE (needs Linux >= 5.13) — run aborts".into()
    });
    let net_denied = matches!(policy.network, Some(Network::Denied));
    if net_denied || !policy.local_ports.is_empty() {
        out.push(if landlock_probe::landlock_net_supported() {
            "network (TCP, per-port): GUARANTEED (Landlock ABI v4+)".into()
        } else {
            "network (TCP): UNAVAILABLE (needs Linux >= 6.7) — run aborts when denial is required".into()
        });
    }
    if policy.isolate_network {
        out.push("network (all protocols off): GUARANTEED via network namespace if CAP_SYS_ADMIN — run aborts otherwise".into());
    }
    let cg = cgroup::cgroup_usable();
    if policy.max_processes.is_some() {
        out.push(if cg {
            "process cap (--max-procs): GUARANTEED (cgroup pids.max, root-proof)".into()
        } else {
            "process cap (--max-procs): BEST-EFFORT (RLIMIT_NPROC — bypassable by root; no usable cgroup here)".into()
        });
    }
    if policy.max_memory_bytes.is_some() {
        out.push(if cg {
            "memory cap (--max-mem): GUARANTEED (RLIMIT_AS + cgroup memory.max)".into()
        } else {
            "memory cap (--max-mem): PARTIAL (RLIMIT_AS address-space cap only; cgroup memory.max unavailable here)".into()
        });
    }
    if policy.max_cpu_secs.is_some() {
        out.push("cpu cap (--max-cpu): GUARANTEED (RLIMIT_CPU, no capability bypass)".into());
    }
    if policy.isolate_pids {
        out.push("pid isolation (--isolate-pids): GUARANTEED via namespaces if CAP_SYS_ADMIN — run aborts otherwise".into());
    }
    if policy.harden_syscalls {
        out.push("seccomp hardening (--seccomp-strict): GUARANTEED (fails closed)".into());
    }
    if policy.deny_unix_sockets {
        out.push("AF_UNIX deny (--deny-unix): GUARANTEED (seccomp, fails closed)".into());
    }
    out
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
