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
#[cfg(target_os = "linux")]
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
#[cfg(target_os = "linux")]
pub use landlock_probe::{landlock_fs_supported, landlock_net_supported};

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
        policy.check_symlinked_roots().map_err(|reason| PolicyError { reason })?;
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
        let (mut cmd, placeholders) = confined_command(policy, command, None)?;
        // The caller owns the child, so nothing here knows when the run ends: the
        // absent-handoff placeholders stay (empty, read-only). Removing them now
        // would detach the read-only binds the agent relies on.
        std::mem::forget(placeholders);
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
        let (mut cmd, placeholders) = confined_command(policy, command, procs)?;
        let child = cmd.spawn().map_err(|e| RunError { reason: format!("spawn: {e}") })?;
        let mut cols = make_collectors(child.id());
        let code = supervise(child, policy.timeout, cg.as_ref().map(|c| c.dir()), &mut cols, sink);
        drop(placeholders);
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
    let (mut cmd, placeholders) = confined_command(policy, command, procs)?;
    let child = cmd.spawn().map_err(|e| RunError { reason: format!("spawn: {e}") })?;
    let code = supervise(child, policy.timeout, cg.as_ref().map(|c| c.dir()), &mut [], &mut VecSink::default());
    drop(placeholders); // the run is over: remove the absent-handoff placeholders
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
    let mut paths: Vec<PathBuf> = paths.iter().map(|p| tartaros_core::resolve_best_effort(p)).collect();
    paths.retain(|p| p.exists());
    paths.sort();
    paths.dedup();
    // An explicit deny on a path that does not exist yet can't be bound
    // read-only (there is nothing to bind) and the whole-root grant would let it
    // be created, so such a policy uses the carve, which withholds the nearest
    // existing ancestor instead. Only one inside a writable root (or /dev) needs
    // that: no write grant reaches one outside them, under either strategy, so
    // it is as unwritable with the bind mounts as with the carve.
    if !absent_write_denies_in_roots(policy).is_empty() {
        return Vec::new();
    }
    // Same for a handoff name that is a symlink resolving nowhere: only the carve,
    // which withholds the link's parent, keeps the link from being replaced.
    if !policy.unresolvable_handoff_links().is_empty() {
        return Vec::new();
    }
    // Nothing to protect, or no way to create a mount namespace on this host: fall
    // back to the Landlock carve (the probe forks, so gate it on paths first).
    if paths.is_empty() || !namespace::mount_ns_capable() {
        return Vec::new();
    }
    paths
}

/// The explicit write denies that do not exist yet and that a write grant would
/// reach: inside a writable root, or /dev (granted to every run). Compared on
/// the resolved paths, so a deny spelt through a symlink into a root counts.
#[cfg(target_os = "linux")]
fn absent_write_denies_in_roots(policy: &Policy) -> Vec<PathBuf> {
    let granted: Vec<PathBuf> = policy
        .writable_roots
        .iter()
        .map(|r| tartaros_core::resolve_best_effort(r))
        .chain(std::iter::once(PathBuf::from("/dev")))
        .collect();
    policy
        .absent_write_denies()
        .into_iter()
        .filter(|d| granted.iter().any(|r| d.starts_with(r)))
        .collect()
}

/// A writable root in which the run cannot create new entries, and why.
#[cfg(target_os = "linux")]
pub struct RootWithoutNewEntries {
    pub root: PathBuf,
    /// The denies below it that the carve withholds it for.
    pub denies: Vec<PathBuf>,
    /// Why the bind-mount strategy, which would lift it, is not used.
    pub because: String,
}

/// The writable roots this policy, on this host, leaves without the right to
/// create new entries directly in them: the carve grants a root's existing
/// children but never the root itself when a deny lies below it. Empty under
/// the bind-mount strategy. Read off the same carve the run uses, so it says
/// exactly what the run will do.
#[cfg(target_os = "linux")]
pub fn roots_without_new_entries(policy: &Policy) -> Vec<RootWithoutNewEntries> {
    use tartaros_core::resolve_best_effort;
    if uses_bind_mounts(policy) {
        return Vec::new();
    }
    let grants = policy.linux_write_allowlist_except(&on_readonly_mount);
    let absent_inside = absent_write_denies_in_roots(policy);
    let because = if !namespace::mount_ns_capable() {
        format!("no mount namespace on this host: {}", namespace::userns_blocker_hint())
    } else if !absent_inside.is_empty() {
        format!(
            "a write deny inside a writable root does not exist yet ({}), and a read-only bind mount needs something to bind",
            absent_inside[0].display()
        )
    } else {
        "a trust-handoff link there resolves nowhere, and a read-only bind mount needs something to bind".into()
    };
    let denied: Vec<PathBuf> = policy
        .fs_rules
        .iter()
        .filter(|r| r.access == tartaros_core::Access::Deny)
        .map(|r| resolve_best_effort(&r.path))
        .chain(policy.trust_handoff_rules().into_iter().map(|r| resolve_best_effort(&r.path)).filter(|p| p.exists()))
        .filter(|p| !on_readonly_mount(p))
        .collect();
    let mut out = Vec::new();
    for root in &policy.writable_roots {
        let r = resolve_best_effort(root);
        if !r.is_dir() || grants.iter().any(|g| *g == r) {
            continue;
        }
        let mut denies: Vec<PathBuf> = denied.iter().filter(|d| d.starts_with(&r) && **d != r).cloned().collect();
        if denies.is_empty() {
            // The root itself is denied (or lies inside a deny): nothing in it is
            // writable, which is not this limit.
            continue;
        }
        denies.sort();
        denies.dedup();
        out.push(RootWithoutNewEntries { root: root.clone(), denies, because: because.clone() });
    }
    out
}

/// Is `p` an existing path on a read-only mount? Such a path cannot be written,
/// unlinked or renamed whatever Landlock allows (a read-only bind of an outer
/// sandbox, say), so the write carve need not withhold its parent.
#[cfg(target_os = "linux")]
fn on_readonly_mount(p: &std::path::Path) -> bool {
    let Some(c) = cstring(p) else { return false };
    let mut sv: libc::statvfs = unsafe { std::mem::zeroed() };
    unsafe { libc::statvfs(c.as_ptr(), &mut sv) == 0 && sv.f_flag & libc::ST_RDONLY != 0 }
}

#[cfg(target_os = "linux")]
fn cstring(p: &std::path::Path) -> Option<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(p.as_os_str().as_bytes()).ok()
}

/// The empty files this run put at absent handoff paths. Dropping it removes
/// each one that is still an empty regular file, so the workspace is left as it
/// was found. A run that is killed outright leaves them behind, empty and
/// read-only (sandbox-runtime leaves its /dev/null mount points the same way).
#[cfg(target_os = "linux")]
#[derive(Default)]
pub(crate) struct Placeholders(Vec<PathBuf>);

#[cfg(target_os = "linux")]
impl Placeholders {
    fn paths(&self) -> impl Iterator<Item = &PathBuf> {
        self.0.iter()
    }
}

#[cfg(target_os = "linux")]
impl Drop for Placeholders {
    fn drop(&mut self) {
        for p in &self.0 {
            if std::fs::symlink_metadata(p).map(|m| m.is_file() && m.len() == 0).unwrap_or(false) {
                let _ = std::fs::remove_file(p);
            }
        }
    }
}

/// Create the placeholder for every absent trust-handoff path under a writable
/// root: an empty 0444 file at its first missing component. Never through a
/// symlinked component (it could point anywhere), created O_EXCL. Fails closed.
#[cfg(target_os = "linux")]
fn create_placeholders(policy: &Policy) -> Result<Placeholders, String> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let roots: Vec<PathBuf> = policy.writable_roots.iter().map(|r| tartaros_core::resolve_best_effort(r)).collect();
    let mut firsts: Vec<PathBuf> = Vec::new();
    for rule in policy.trust_handoff_rules() {
        let mut p = rule.path.clone();
        if std::fs::symlink_metadata(&p).is_ok() {
            continue;
        }
        let in_git = p.components().any(|c| c.as_os_str() == ".git");
        while let Some(parent) = p.parent() {
            if std::fs::symlink_metadata(parent).is_ok() {
                break;
            }
            p = parent.to_path_buf();
        }
        // Only at a root's top level (`.mcp.json`, `.claude` for
        // `.claude/settings.json`) and in a repository's git internals: the rules
        // also name every absent handoff file in every nested directory (macOS
        // denies those by pattern), and a placeholder in each would litter the
        // whole tree.
        let at_top = p.parent().map(|d| roots.iter().any(|r| d == r.as_path())).unwrap_or(false);
        if !at_top && !in_git {
            continue;
        }
        let parent_is_dir = p.parent().map(|d| d.is_dir()).unwrap_or(false);
        let in_root = p.parent().map(|d| roots.iter().any(|r| d.starts_with(r))).unwrap_or(false);
        if parent_is_dir && in_root && !has_symlink_component(&p) {
            firsts.push(p);
        }
    }
    firsts.sort();
    firsts.dedup();
    let mut made = Placeholders::default();
    for p in firsts {
        match std::fs::OpenOptions::new().write(true).create_new(true).mode(0o444).open(&p) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            // A directory we cannot write to is one the agent cannot create in
            // either (same user, and Landlock grants no more than the mode).
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => continue,
            Err(e) => return Err(format!("handoff placeholder {}: {e}; refusing to run with it unprotected", p.display())),
        }
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o444));
        made.0.push(p);
    }
    Ok(made)
}

/// Mount-level hardening for a run with its own mount namespace, built in the
/// parent (the child must not allocate): `pins` are bound onto themselves
/// read-write, `seal` remounted read-only, `hide` covered with an empty tmpfs,
/// `hide_files` covered with /dev/null.
#[cfg(target_os = "linux")]
#[derive(Default)]
struct MountPlan {
    pins: Vec<std::ffi::CString>,
    seal: Vec<std::ffi::CString>,
    hide: Vec<std::ffi::CString>,
    hide_files: Vec<std::ffi::CString>,
}

#[cfg(target_os = "linux")]
fn mount_plan(policy: &Policy, binds: &[PathBuf]) -> MountPlan {
    use tartaros_core::resolve_best_effort;
    let roots: Vec<PathBuf> = policy
        .writable_roots
        .iter()
        .map(|r| resolve_best_effort(r))
        .filter(|r| r.exists())
        .collect();
    let under = |p: &std::path::Path, set: &[PathBuf]| set.iter().any(|r| p.starts_with(r));
    // Pins: the roots and /dev (kept writable), then every dot-directory between
    // a root and a protected path (`.git` for `.git/config`), outermost first. A
    // root inside a protected path is not pinned: the read-only bind over that
    // path must cover it (`--write-deny work/proj` with a root `work/proj/out`).
    let mut pins: Vec<PathBuf> = roots.iter().filter(|r| !under(r, binds)).cloned().collect();
    pins.push(PathBuf::from("/dev"));
    let mut holders: Vec<PathBuf> = Vec::new();
    for b in binds {
        let Some(root) = roots.iter().filter(|r| b.starts_with(r)).max_by_key(|r| r.components().count()) else {
            continue;
        };
        let mut a = b.parent();
        while let Some(d) = a {
            if d == root.as_path() || !d.starts_with(root) {
                break;
            }
            if d.file_name().map(|n| n.to_string_lossy().starts_with('.')).unwrap_or(false) && d.is_dir() {
                holders.push(d.to_path_buf());
            }
            a = d.parent();
        }
    }
    // An explicit deny inside a root (`--write-deny`, `--read-deny`) pins every
    // directory between the root and it, whatever its name: `mv dir aside &&
    // mkdir dir` would otherwise put a fresh, writable (or readable) path where
    // the deny was.
    let explicit = policy
        .fs_rules
        .iter()
        .filter(|r| r.access == tartaros_core::Access::Deny)
        .map(|r| resolve_best_effort(&r.path))
        .chain(policy.read_denies.iter().map(|d| resolve_best_effort(d)));
    for d in explicit {
        let Some(root) = roots.iter().filter(|r| d.starts_with(r)).max_by_key(|r| r.components().count()) else {
            continue;
        };
        let mut a = d.parent();
        while let Some(dir) = a {
            if dir == root.as_path() || !dir.starts_with(root) {
                break;
            }
            if dir.is_dir() {
                holders.push(dir.to_path_buf());
            }
            a = dir.parent();
        }
    }
    holders.sort_by_key(|h| h.components().count());
    holders.dedup();
    pins.extend(holders);
    // Seal: every mount point outside the roots, /dev, /proc and /sys.
    let keep: Vec<PathBuf> = ["/dev", "/proc", "/sys"].iter().map(PathBuf::from).chain(roots.iter().cloned()).collect();
    let mut seal: Vec<PathBuf> = mount_points().into_iter().filter(|m| !under(m, &keep)).collect();
    seal.sort();
    seal.dedup();
    // Hide: read-denied directories that hold no root and no read-allow, and do not
    // sit inside a root (a deny inside the workspace stays a Landlock deny).
    let allows: Vec<PathBuf> = policy.read_allows.iter().map(|a| resolve_best_effort(a)).collect();
    let mut hide: Vec<PathBuf> = policy
        .read_denies
        .iter()
        .map(|d| resolve_best_effort(d))
        .filter(|d| d.is_dir() && d.parent().is_some())
        .filter(|d| !under(d, &roots))
        .filter(|d| !roots.iter().chain(allows.iter()).any(|r| r.starts_with(d)))
        .collect();
    // A read-denied directory that does hold a root or a read-allow (a deny on
    // `/` with the system dirs and the workspace allowed back, the granted
    // model) cannot be covered whole. Landlock keeps what is in it unreadable, but
    // it does not mediate connect(): a unix socket there would stay reachable. So
    // every entry in it that is neither kept nor on the way to a kept path is
    // covered instead, one level at a time.
    let kept: Vec<PathBuf> = roots
        .iter()
        .cloned()
        .chain(allows.iter().filter(|a| a.exists()).cloned())
        .chain(["/dev", "/proc", "/sys"].iter().map(PathBuf::from))
        .collect();
    let mut hide_files: Vec<PathBuf> = Vec::new();
    let holding: Vec<PathBuf> = policy
        .read_denies
        .iter()
        .map(|d| resolve_best_effort(d))
        .filter(|d| d.is_dir() && !under(d, &roots))
        .filter(|d| kept.iter().any(|k| k.starts_with(d)))
        .collect();
    for d in holding {
        hide_beside(&d, &kept, &mut hide, &mut hide_files);
    }
    hide.sort();
    hide.dedup();
    hide_files.sort();
    hide_files.dedup();
    let cs = |v: Vec<PathBuf>| v.iter().filter_map(|p| cstring(p)).collect();
    MountPlan { pins: cs(pins), seal: cs(seal), hide: cs(hide), hide_files: cs(hide_files) }
}

/// An `O_PATH` descriptor for a Landlock rule. Not `landlock::PathFd`: it opens
/// through `std::fs::OpenOptions`, and Rust's std on musl drops `O_PATH` from
/// `custom_flags`, so the open became a plain read open, which blocks forever
/// on a FIFO (a stray `/tmp/*-pipe` under a carved read deny hung every run)
/// and fails with EACCES where O_PATH would not.
#[cfg(target_os = "linux")]
fn path_fd(path: &std::path::Path) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

/// The entries of `dir` to cover so that only `kept` paths, and the directories on
/// the way to them, stay reachable: directories go to `dirs`, any other entry
/// (a socket, a fifo, a file) to `files`. Symlinks are left alone: what they lead
/// to is covered, or kept, by its own path. A directory that cannot be listed
/// is left as it is (Landlock still keeps its files unreadable).
#[cfg(target_os = "linux")]
fn hide_beside(dir: &std::path::Path, kept: &[PathBuf], dirs: &mut Vec<PathBuf>, files: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else { continue };
        if meta.file_type().is_symlink() || kept.iter().any(|k| path.starts_with(k)) {
            continue;
        }
        if kept.iter().any(|k| k.starts_with(&path)) {
            if meta.is_dir() {
                hide_beside(&path, kept, dirs, files);
            }
            continue;
        }
        if meta.is_dir() {
            dirs.push(path);
        } else {
            files.push(path);
        }
    }
}

/// The mount points of this process's mount namespace (field 5 of
/// /proc/self/mountinfo, with its octal escapes undone).
#[cfg(target_os = "linux")]
fn mount_points() -> Vec<PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    let text = std::fs::read("/proc/self/mountinfo").unwrap_or_default();
    let mut out = Vec::new();
    for line in text.split(|b| *b == b'\n') {
        let Some(field) = line.split(|b| *b == b' ').nth(4) else { continue };
        let mut bytes = Vec::with_capacity(field.len());
        let mut i = 0;
        while i < field.len() {
            if field[i] == b'\\' && i + 3 < field.len() && field[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
                bytes.push((field[i + 1] - b'0') * 64 + (field[i + 2] - b'0') * 8 + (field[i + 3] - b'0'));
                i += 4;
            } else {
                bytes.push(field[i]);
                i += 1;
            }
        }
        out.push(PathBuf::from(std::ffi::OsString::from_vec(bytes)));
    }
    out
}

/// Does every run on this host get a private PID namespace (and the rest of the
/// mount-level hardening) by default? True wherever a mount namespace can be
/// created: root with CAP_SYS_ADMIN, or a host that allows unprivileged user
/// namespaces.
#[cfg(target_os = "linux")]
pub fn namespaces_by_default() -> bool {
    namespace::mount_ns_capable()
}

/// Would this policy be enforced with the read-only bind-mount strategy (whole
/// workspace writable + handoff bound read-only), rather than the write carve?
/// Used by the CLI to decide whether to warn about the carve's create-at-root
/// limitation.
#[cfg(target_os = "linux")]
pub fn uses_bind_mounts(policy: &Policy) -> bool {
    !robind_targets(policy).is_empty()
}

#[cfg(target_os = "linux")]
fn confined_command(
    policy: &Policy,
    command: &[String],
    cgroup_procs: Option<String>,
) -> Result<(std::process::Command, Placeholders), RunError> {
    use landlock::{
        ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, NetPort, PathBeneath,
        Ruleset, RulesetAttr, RulesetCreatedAttr,
    };
    use tartaros_core::Network;
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    let err = |m: String| RunError { reason: m };

    // Can this run have its own mount namespace? Root with CAP_SYS_ADMIN can;
    // otherwise only if the host allows an unprivileged user namespace (probed).
    let ns_capable = namespace::mount_ns_capable();
    // --isolate-proc: with namespaces available, give the agent a private PID
    // namespace and a fresh /proc instead of the Landlock read-deny on /proc. The
    // deny also hid the agent's OWN /proc/self (status, maps), breaking ordinary
    // tools; the namespace hides every host process (the supervisor included)
    // while /proc/self keeps working. Without namespaces the deny stays: it still
    // protects, it is just blunter.
    //
    // With namespaces available every run gets that PID namespace, as bubblewrap
    // gives sandbox-runtime and Codex: the agent cannot signal or trace a host
    // process (it cannot name one), and when the supervisor goes away the whole
    // namespace goes with it, background children included. A run with no
    // network grant at all (no --net, port, domain or egress namespace) also gets
    // an empty network namespace: abstract unix sockets live per network
    // namespace, and Landlock on this kernel generation does not scope them.
    let default_netns = ns_capable
        && !matches!(policy.network, Some(Network::Allowed))
        && policy.local_ports.is_empty()
        && policy.allow_domains.is_empty()
        && policy.egress_netns.is_none();
    let nsdefault_policy;
    let policy = if ns_capable {
        nsdefault_policy = Policy {
            isolate_pids: true,
            isolate_process_info: false,
            isolate_network: policy.isolate_network || default_netns,
            ..policy.clone()
        };
        &nsdefault_policy
    } else {
        policy
    };

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
    // With a mount namespace the temporary placeholders below cover the same
    // paths and leave nothing behind, so the permanent files are not made.
    if policy.materialize_absent_handoff && !ns_capable {
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
        let fd = match path_fd(&p) {
            Ok(fd) => fd,
            Err(_) => continue,
        };
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, read_only))
            .map_err(|e| err(format!("add read rule {}: {e}", p.display())))?;
    }

    // The nearest existing ancestor of a read deny that does not exist yet is
    // withheld by the read carve; it may still be listed (ls ~ keeps working),
    // and so may what appears in it later, but no file in it can be read.
    for p in policy.absent_read_deny_holders() {
        let Ok(fd) = path_fd(&p) else { continue };
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, AccessFs::ReadDir))
            .map_err(|e| err(format!("add list rule {}: {e}", p.display())))?;
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
    let write_grants: Vec<PathBuf> = if use_bind_mounts {
        policy.writable_roots.clone()
    } else {
        policy.linux_write_allowlist_except(&on_readonly_mount)
    };
    // Absent handoff paths: with a mount namespace, an empty read-only file is
    // put at the first missing component of each (`.git/hooks`, `.mcp.json`,
    // `.claude` for `.claude/settings.json`) and bound read-only, so the agent can
    // neither create the path nor a symlink in its place. sandbox-runtime does the
    // same with /dev/null. The files are removed when the run ends. Created after
    // the carve above, which must not see them as existing denies.
    let placeholders = if ns_capable { create_placeholders(policy).map_err(err)? } else { Placeholders::default() };
    let plan = if ns_capable {
        let binds: Vec<PathBuf> = robind_paths.iter().chain(placeholders.paths()).cloned().collect();
        mount_plan(policy, &binds)
    } else {
        MountPlan::default()
    };
    for p in &write_grants {
        let fd = match path_fd(p) {
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
    let dev_fd = path_fd(std::path::Path::new("/dev")).map_err(|e| err(format!("open /dev: {e}")))?;
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
    // A private /dev/shm whenever this run can have its own mount namespace: the
    // host-shared POSIX shm dir is otherwise a cross-process channel out of the
    // box (and a place to leave files behind). On a host that forbids namespaces
    // the dir stays shared — the same as before, reported by `explain`.
    let private_shm = ns_capable;
    // Compile the seccomp BPF programs HERE in the parent (allocation is fine),
    // not in pre_exec — building a BPF program after fork could deadlock a child of
    // a multithreaded parent (broker/collector threads) on the malloc lock (review
    // #7). The child only applies them (prctl + apply_filter, no allocation).
    let no_net_grant = restrict_net
        && policy.local_ports.is_empty()
        && policy.allow_domains.is_empty()
        && policy.egress_netns.is_none();
    let seccomp_progs = seccomp::compile_all(deny_unix, harden_syscalls, restrict_net, no_net_grant)
        .map_err(|e| err(format!("seccomp compile: {e}")))?;
    // Read-only bind-mount targets (built here in the parent; the pre_exec closure
    // must not allocate/stat). Empty unless we chose the bind-mount strategy.
    let robind_cstrings: Vec<std::ffi::CString> =
        robind_paths.iter().chain(placeholders.paths()).filter_map(|p| cstring(p)).collect();
    let MountPlan { pins, seal, hide, hide_files } = plan;
    let mount_ns = ns_capable || isolate_pids || isolate_network;
    // Pre-build (in the parent) everything pre_exec would otherwise allocate after
    // the fork (review #7): the cgroup.procs path as a CString, and the user-ns
    // uid/gid maps (euid/egid are preserved across fork).
    let cgroup_procs_c: Option<std::ffi::CString> =
        cgroup_procs.as_ref().and_then(|p| std::ffi::CString::new(p.as_str()).ok());
    // NET-01: path to the prepared egress network namespace the child must join
    // (set by the CLI when it built the scoped netns). Pre-built here so pre_exec
    // only does open/setns/close — no allocation after the fork.
    let egress_netns_c: Option<std::ffi::CString> = policy
        .egress_netns
        .as_ref()
        .and_then(|n| std::ffi::CString::new(format!("/var/run/netns/{n}")).ok());
    let (userns_uid_map, userns_gid_map) = namespace::uid_gid_maps();
    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]);
    // Scrub the inherited environment to the policy's allowlist (F-13): a secret in
    // the launcher's env (AWS_*, *_TOKEN) is inherited at exec and is NOT governed
    // by Landlock/seccomp, so by default we hand the child only the safe allowlist.
    if let Some(env) = policy.child_env() {
        cmd.env_clear();
        cmd.envs(env);
    }
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
            // NET-01: join the prepared egress network namespace (scoped veth to the
            // broker, no default route). Must happen while still root in the host
            // user namespace (joining a netns needs CAP_SYS_ADMIN in its owning
            // userns) — so BEFORE any enter_user_namespace below. Fails closed.
            if let Some(nspath) = &egress_netns_c {
                let fd = libc::open(nspath.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
                if fd < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setns(fd, libc::CLONE_NEWNET) != 0 {
                    let e = std::io::Error::last_os_error();
                    libc::close(fd);
                    return Err(e);
                }
                libc::close(fd);
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
            let need_userns = not_root
                && (isolate_pids || isolate_network || !robind_cstrings.is_empty() || private_shm);
            if need_userns {
                namespace::enter_user_namespace(&userns_uid_map, &userns_gid_map)?;
            }
            if isolate_pids || isolate_network {
                namespace::enter_namespaces(isolate_pids, isolate_network, &seccomp_progs)?;
            }
            // Everything below mounts, so it needs a mount namespace of our own:
            // isolate_pids already made one; otherwise (including --isolate-net
            // alone, which unshares only the network) make it here, so nothing can
            // land on the host's tree. We hold CAP_SYS_ADMIN now, as root or via
            // the user namespace above.
            if mount_ns && !isolate_pids {
                namespace::enter_private_mount_ns()?;
            }
            // Pins first, while every mount still has its own flags: the writable
            // roots and /dev keep write access through the seal below, and the
            // directories that hold a protected path become mount points that
            // cannot be renamed away. Fails closed.
            namespace::pin_mounts(&pins)?;
            // Read-only bind mounts for the trust-handoff set (so the workspace can
            // be granted writable without the handoff being writable), and for the
            // placeholders of the absent handoff paths. Fails closed — a mount
            // error aborts before the workspace is ever exposed writable.
            if !robind_cstrings.is_empty() {
                namespace::setup_ro_binds(&robind_cstrings, false)?;
            }
            // Hide the read-denied directories (unix sockets there stop resolving).
            namespace::hide_dirs(&hide)?;
            namespace::hide_files(&hide_files)?;
            // Everything that is not a writable root or /dev goes read-only, so
            // chmod/utimes/xattrs outside the roots fail too.
            namespace::seal_readonly(&seal);
            // Isolate /dev/shm from the host: a fresh private tmpfs so the shared
            // POSIX shm dir is not a side channel.
            if mount_ns {
                namespace::mount_private_shm()?;
            }
            // Kill-switch (supervisor loss): die if our parent dies, even on a
            // SIGKILL of the supervisor that never runs destroy_cgroup.
            //   - In a PID namespace this is a COMPLETE tree-kill: the agent's
            //     parent is the namespace's PID 1 init, whose parent is the shim
            //     (each carries the same request one level up), so the chain
            //     supervisor→shim→init→agent collapses and the whole namespace —
            //     every descendant — is torn down. Nothing outlives the box.
            //   - Without it, PR_SET_PDEATHSIG reaps only THIS (direct child)
            //     process; a grandchild the agent forked can be reparented to init
            //     and survive. The full guarantee needs the PID namespace (which
            //     the hostile-code / multi-tenant profiles enable by default).
            if isolate_pids {
                namespace::set_pdeathsig_kill_under_init();
            } else {
                namespace::set_pdeathsig_kill();
            }
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
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            // Close inherited non-stdio fds just before exec (defense-in-depth):
            // an fd opened by the parent bypasses path-based confinement because
            // the open already happened. Done last so the ruleset fd was still live.
            namespace::cloexec_inherited_fds();
            Ok(())
        });
    }
    Ok((cmd, placeholders))
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
    let ns_capable = namespace::mount_ns_capable();
    if ns_capable {
        out.push("pid isolation: ON by default (private PID namespace + fresh /proc: host processes cannot be seen or signalled; the whole tree dies with the run)".into());
    } else if policy.isolate_pids {
        out.push("pid isolation (--isolate-pids): GUARANTEED via namespaces if CAP_SYS_ADMIN — run aborts otherwise".into());
    } else {
        out.push("pid isolation: OFF (this host forbids namespaces; host processes are visible and a background child can outlive the run)".into());
    }
    if policy.isolate_process_info && !ns_capable {
        out.push("process info (--isolate-proc): GUARANTEED (Landlock read-deny on /proc; also hides the agent's own /proc/self — no namespaces on this host)".into());
    }
    let no_net_grant = !matches!(policy.network, Some(Network::Allowed))
        && policy.local_ports.is_empty()
        && policy.allow_domains.is_empty()
        && policy.egress_netns.is_none();
    if ns_capable && no_net_grant && !policy.isolate_network {
        out.push("network namespace: ON by default (no network grant: no egress on any protocol, abstract unix sockets of the host unreachable)".into());
    }
    out.push(if ns_capable {
        "outside the writable roots: READ-ONLY mounts (chmod, utimes, xattrs refused too); absent handoff paths blocked by read-only placeholders; read-denied dirs hidden".into()
    } else {
        "outside the writable roots: Landlock only (chmod, utimes and xattrs are not mediated; absent handoff paths can be created — no namespaces on this host)".into()
    });
    out.push(if ns_capable {
        "/dev/shm: PRIVATE (fresh tmpfs in the run's mount namespace)".into()
    } else {
        "/dev/shm: SHARED with the host (this host forbids the mount namespace a private one needs)".into()
    });
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

    #[cfg(target_os = "linux")]
    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("tartaros-rootent-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        tartaros_core::resolve_best_effort(&d)
    }

    #[cfg(target_os = "linux")]
    fn write_deny(p: PathBuf) -> tartaros_core::FsRule {
        tartaros_core::FsRule { path: p, access: tartaros_core::Access::Deny, even_if_absent: true }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn only_an_absent_deny_a_write_grant_reaches_keeps_the_bind_mounts_off() {
        let root = scratch("absent");
        let outside = scratch("absent-outside");
        let link = scratch("absent-link").join("into-root");
        let _ = std::os::unix::fs::symlink(&root, &link);
        let policy = Policy {
            writable_roots: vec![root.clone()],
            fs_rules: vec![
                write_deny(root.join("not-yet/x")),
                write_deny(outside.join("not-yet/x")),
                write_deny(link.join("via-link")),
                write_deny(PathBuf::from("/dev/tartaros-not-yet")),
            ],
            ..Default::default()
        };
        let got = absent_write_denies_in_roots(&policy);
        assert!(got.contains(&root.join("not-yet/x")), "{got:?}");
        assert!(got.contains(&root.join("via-link")), "a deny spelt through a link into the root: {got:?}");
        assert!(got.contains(&PathBuf::from("/dev/tartaros-not-yet")), "{got:?}");
        assert!(!got.iter().any(|p| p.starts_with(&outside)), "no grant reaches it: {got:?}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_absent_deny_inside_a_root_is_said_whatever_the_host() {
        // The carve withholds the root for it on every host: no bind mount can
        // cover a path that is not there. The warning used to skip it.
        let root = scratch("said-absent");
        let policy = Policy {
            writable_roots: vec![root.clone()],
            fs_rules: vec![write_deny(root.join("not-yet"))],
            ..Default::default()
        };
        let got = roots_without_new_entries(&policy);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].root, root);
        assert_eq!(got[0].denies, vec![root.join("not-yet")]);
        assert!(!policy.linux_write_allowlist_except(&on_readonly_mount).contains(&root));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_existing_deny_is_said_exactly_when_the_carve_is_used() {
        let root = scratch("said-existing");
        std::fs::create_dir_all(root.join("claude")).unwrap();
        let policy = Policy {
            writable_roots: vec![root.clone()],
            fs_rules: vec![write_deny(root.join("claude"))],
            ..Default::default()
        };
        let got = roots_without_new_entries(&policy);
        if uses_bind_mounts(&policy) {
            assert!(got.is_empty(), "the bind mounts let the root take new entries");
        } else {
            assert_eq!(got.len(), 1);
            assert_eq!(got[0].denies, vec![root.join("claude")]);
            assert!(got[0].because.starts_with("no mount namespace"), "{}", got[0].because);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_absent_deny_outside_the_roots_does_not_change_the_strategy() {
        let root = scratch("strategy");
        std::fs::create_dir_all(root.join("claude")).unwrap();
        let alone = Policy {
            writable_roots: vec![root.clone()],
            fs_rules: vec![write_deny(root.join("claude"))],
            ..Default::default()
        };
        let mut with_outside = alone.clone();
        with_outside.fs_rules.push(write_deny(scratch("strategy-outside").join("not-yet/x")));
        assert_eq!(uses_bind_mounts(&alone), uses_bind_mounts(&with_outside));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_root_with_nothing_denied_below_is_not_said() {
        let root = scratch("clean");
        let policy = Policy { writable_roots: vec![root], ..Default::default() };
        assert!(roots_without_new_entries(&policy).is_empty());
    }
}
