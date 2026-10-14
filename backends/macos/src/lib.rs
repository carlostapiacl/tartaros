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
    RunOutcome, HANDOFF_CONFIG_NAMES, HANDOFF_GIT_NAMES,
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
        // Fail closed on Linux-only hardening: Seatbelt cannot provide a PID /
        // network namespace or a seccomp syscall filter, so honouring a policy
        // that requested one by silently running WITHOUT it would hand back a
        // weaker sandbox than asked for (the P0-2 class). Refuse with a clear
        // message instead — a capability we cannot provide is never silently
        // downgraded. (RLIMIT-based caps and FS/trust-handoff ARE provided here.)
        let mut unsupported = Vec::new();
        if policy.isolate_pids {
            unsupported.push("--isolate-pids (PID namespace)");
        }
        if policy.isolate_network {
            unsupported.push("--isolate-net (network namespace)");
        }
        if policy.harden_syscalls {
            unsupported.push("--seccomp-strict (seccomp syscall filter)");
        }
        if policy.deny_unix_sockets {
            unsupported.push("--deny-unix (seccomp AF_UNIX deny)");
        }
        if !unsupported.is_empty() {
            return Err(PolicyError {
                reason: format!(
                    "unsupported on macOS (Seatbelt cannot provide these): {}. \
                     Run on Linux for this hardening, or drop the flags / use \
                     --profile local-agent.",
                    unsupported.join(", ")
                ),
            });
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
        // Tag every deny with a per-run message so each kernel denial is
        // attributable in the macOS unified log (consumers filter on "_SBX").
        let tag = log_tag(command);
        let profile = compile_profile_tagged(policy, Some(&tag));
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
                // Mark every inherited fd >= 3 close-on-exec, up to the current fd
                // limit (not a fixed 1024). CLOEXEC, not close(): a leaked fd still
                // does not survive into the exec'd agent (FD-1 defense), but we must
                // NOT close std's exec-status pipe here — close()ing it makes std
                // abort ("output.write ... aborting") when an exec FAILS, which broke
                // node / git / python3 under the sandbox on macOS. CLOEXEC leaves the
                // pipe usable for std's failed-exec report and drops it on success.
                let mut hi: libc::rlimit = std::mem::zeroed();
                let max_fd = if libc::getrlimit(libc::RLIMIT_NOFILE, &mut hi) == 0 && hi.rlim_cur != libc::RLIM_INFINITY {
                    (hi.rlim_cur as i32).min(1 << 20)
                } else {
                    1 << 16
                };
                for fd in 3..max_fd {
                    let flags = libc::fcntl(fd, libc::F_GETFD);
                    if flags >= 0 {
                        let _ = libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
                    }
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

/// macOS analogue of the Linux `host_blocks_run`: why `run` would refuse this
/// policy on macOS (Seatbelt cannot provide the Linux-only hardening knobs), or
/// None. `explain` exits non-zero when this is Some, matching `run` — so an audit
/// never shows a green ✓ for a policy this host cannot enforce.
pub fn host_blocks_run(policy: &Policy) -> Option<String> {
    let mut unsupported = Vec::new();
    if policy.isolate_pids {
        unsupported.push("--isolate-pids (PID namespace)");
    }
    if policy.isolate_network {
        unsupported.push("--isolate-net (network namespace)");
    }
    if policy.harden_syscalls {
        unsupported.push("--seccomp-strict (seccomp syscall filter)");
    }
    if policy.deny_unix_sockets {
        unsupported.push("--deny-unix (seccomp AF_UNIX deny)");
    }
    if unsupported.is_empty() {
        None
    } else {
        Some(format!(
            "unsupported on macOS (Seatbelt cannot provide these): {}. Run on Linux \
             for this hardening, or drop the flags / use --profile local-agent.",
            unsupported.join(", ")
        ))
    }
}

/// Build the Seatbelt SBPL profile. In SBPL the LAST matching rule wins, so
/// Resolve what this policy actually enforces on macOS (Seatbelt + RLIMIT), so a
/// user can verify guarantees before running. The Linux-only hardening knobs are
/// reported UNSUPPORTED here (validate() also refuses them — never silent).
pub fn enforcement_report(policy: &Policy) -> Vec<String> {
    let mut out = vec![
        "filesystem / trust-handoff: GUARANTEED (Seatbelt)".to_string(),
        "network (default-deny + per-port): GUARANTEED (Seatbelt)".to_string(),
    ];
    if policy.max_memory_bytes.is_some() {
        out.push("memory cap (--max-mem): BEST-EFFORT (RLIMIT_AS)".into());
    }
    if policy.max_processes.is_some() {
        out.push("process cap (--max-procs): BEST-EFFORT (RLIMIT_NPROC — no cgroup on macOS)".into());
    }
    if policy.max_cpu_secs.is_some() {
        out.push("cpu cap (--max-cpu): GUARANTEED (RLIMIT_CPU)".into());
    }
    for (flag, on) in [
        ("--isolate-pids", policy.isolate_pids),
        ("--isolate-net", policy.isolate_network),
        ("--seccomp-strict", policy.harden_syscalls),
        ("--deny-unix", policy.deny_unix_sockets),
    ] {
        if on {
            out.push(format!("{flag}: UNSUPPORTED on macOS (Seatbelt) — run is refused"));
        }
    }
    out
}

/// every deny is emitted AFTER the broad allows, and the trust-handoff denies
/// cannot be re-allowed.
pub fn compile_profile(policy: &Policy) -> String {
    build_profile(policy)
}

/// Like [`compile_profile`], but tag every `deny` rule with `(with message
/// "<tag>")` so each kernel sandbox denial is attributable in the macOS unified
/// log. Consumers (e.g. seisin) filter with `eventMessage ENDSWITH "_SBX"` and
/// match the embedded command, so a denial is attributable even after the denied
/// process has exited. `None` = no tags (identical to `compile_profile`).
pub fn compile_profile_tagged(policy: &Policy, log_tag: Option<&str>) -> String {
    let profile = build_profile(policy);
    match log_tag {
        Some(tag) => tag_deny_rules(&profile, tag),
        None => profile,
    }
}

fn build_profile(policy: &Policy) -> String {
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
    // sysctl-read: allow broadly, then deny the process-enumeration namespace.
    // A narrow name whitelist is tempting but fragile — runtimes like V8/Node read
    // a wide, version-dependent set of hw.*/machdep.* keys (cache line size, CPU
    // feature bits, frequencies), and a single DENIED read returns an error the
    // runtime mishandles into a bogus size, aborting with a LowLevelAlloc overflow.
    // So we allow the harmless hardware/OS keys wholesale and carve out only what
    // leaks other processes: kern.proc* / kern.procargs* (args, env, process list).
    // Deny comes last (last match wins) and holds regardless of isolate_process_info.
    p.push_str("(allow sysctl-read)\n");
    p.push_str("(deny sysctl-read (sysctl-name-prefix \"kern.proc\"))\n");
    p.push_str("(deny sysctl-read (sysctl-name-prefix \"kern.procargs\"))\n");

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
    // Specific AF_UNIX sockets the agent may reach (e.g. a per-run audit socket).
    // Everything else stays denied by `(deny default)` — Seatbelt can scope this
    // to one path, which the Linux/seccomp backend cannot. Canonicalize so the
    // literal matches the real path (symlinked temp dirs).
    for path in &policy.allow_unix_socket_paths {
        let real = path.canonicalize().unwrap_or_else(|_| path.clone());
        p.push_str(&format!(
            "(allow network-outbound (remote unix-socket (path-literal {})))\n",
            quote(&real)
        ));
    }

    // Writable roots.
    for root in &policy.writable_roots {
        p.push_str(&format!("(allow file-write* (subpath {}))\n", quote(root)));
    }

    // Denies LAST so they win. Explicit (concrete-path) deny rules first.
    let denies: Vec<FsRule> = policy
        .fs_rules
        .iter()
        .filter(|r| r.access == Access::Deny)
        .cloned()
        .collect();
    for rule in &denies {
        emit_deny(&mut p, &rule.path, &policy.writable_roots);
    }

    // Trust-handoff set, at ANY depth under each writable root. On macOS Seatbelt
    // we express this as regex path rules instead of walking the filesystem: it is
    // both cheap (no O(tree) stat storm at compile time — a `--write /tmp` tree can
    // be huge) and strictly more correct than enumerating existing paths. Matching
    // by pattern also covers handoff paths created AFTER the box starts, and — being
    // any-depth — defeats the ancestor-rename move (wherever the path lands under
    // the root it still matches; outside the root is not writable anyway).
    for root in &policy.writable_roots {
        emit_handoff_regex(&mut p, root);
    }

    // Read carve: deny-reads and re-allow-reads interleave by SPECIFICITY — the
    // most specific (deepest) path wins, which is the sandbox-runtime rule. A naive
    // "all denies then all allows" is wrong: a deny that sits INSIDE a re-allowed
    // branch (deny runs/ → allow runs/mine/ → deny runs/mine/settings.json) must
    // still win, but emitting all allows last would re-open it. Seatbelt is
    // last-match-wins, so we sort every read rule by path depth ascending and emit
    // least-specific first; the deepest rule lands last and takes precedence.
    // Canonicalize first (Seatbelt matches the real path, e.g. /tmp -> /private/tmp).
    let mut read_rules: Vec<(PathBuf, bool)> = Vec::new(); // (path, is_allow)
    for path in &policy.read_denies {
        read_rules.push((canonical_best_effort(path), false));
    }
    for path in &policy.read_allows {
        read_rules.push((canonical_best_effort(path), true));
    }
    // Specificity = number of path components, then string length as a tiebreak.
    read_rules.sort_by_key(|(path, _)| (path.components().count(), path.as_os_str().len()));
    for (real, is_allow) in &read_rules {
        if *is_allow {
            p.push_str(&format!("(allow file-read* (subpath {}))\n", quote(real)));
        } else {
            p.push_str(&format!("(deny file-read* (subpath {}))\n", quote(real)));
            p.push_str(&format!("(deny file-read* (literal {}))\n", quote(real)));
        }
    }

    // Single-segment glob denies (e.g. ~/.codex/*.config.toml) as anchored
    // regexes. Emitted LAST so a glob read-deny wins over the broad file-read*
    // allow. `*`/`?` match within one segment only (they never cross `/`).
    for g in &policy.glob_denies {
        let re = glob_to_anchored_regex(&g.pattern);
        if g.write {
            p.push_str(&format!("(deny file-write* (regex #\"{re}\"))\n"));
        }
        if g.read {
            p.push_str(&format!("(deny file-read* (regex #\"{re}\"))\n"));
        }
    }

    p
}

/// Translate a single-segment glob (absolute path with `*`/`?`, no `**`) into an
/// anchored Seatbelt regex. `*` → `[^/]*`, `?` → `[^/]`; every other character is
/// escaped as a literal. (The CLI unwraps single-char classes `[x]` before this,
/// so brackets arriving here are treated literally.)
fn glob_to_anchored_regex(pattern: &str) -> String {
    let mut out = String::from("^");
    for c in pattern.chars() {
        match c {
            '*' => out.push_str("[^/]*"),
            '?' => out.push_str("[^/]"),
            '.' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '^' | '$' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            '"' => out.push_str("\\\""),
            _ => out.push(c),
        }
    }
    out.push('$');
    out
}

/// Deny write to a protected path, plus ancestor move-blocking: renaming any
/// ancestor up to (but not including) the writable root would relocate the
/// protected path out from under its deny, so unlink/rename is denied on each
/// ancestor and on the path itself. `file-write-unlink` is what rename/delete use.
fn emit_deny(p: &mut String, path: &Path, roots: &[PathBuf]) {
    // Canonicalize so the deny matches the real path Seatbelt sees — the writable
    // roots are already canonical, so a deny under /tmp/... must become
    // /private/tmp/... or it would not match (and the write would leak). The path
    // may not exist yet (deny-even-if-absent), so resolve the nearest existing
    // ancestor and reattach the rest.
    let path = &canonical_best_effort(path);
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

/// Emit deny rules for the trust-handoff set at ANY depth under `root`, as
/// Seatbelt regexes rather than a filesystem walk. For each handoff name we deny
/// `file-write*` on the path itself and everything under it, whether it sits
/// directly in the root or nested arbitrarily deep. `file-write*` subsumes
/// `file-write-unlink`, so rename/delete of a protected path is covered; and
/// because the match is any-depth, renaming an ancestor to relocate the path
/// cannot escape it (it would still match under the root, and outside the root
/// is not writable). Absent paths are covered too — the pattern does not require
/// the path to exist, which is the point of a pre-planting defense.
fn emit_handoff_regex(p: &mut String, root: &Path) {
    let root_re = regex_escape(&root.to_string_lossy());
    let mut emit = |name: &str| {
        let name_re = regex_escape(name);
        // ^<root>(/.*)?/<name>(/.*)?$  — <name> directly in root OR nested at any
        // depth; trailing (/.*)? so a protected directory's whole subtree matches.
        p.push_str(&format!(
            "(deny file-write* (regex #\"^{root_re}(/.*)?/{name_re}(/.*)?$\"))\n"
        ));
    };
    for name in HANDOFF_CONFIG_NAMES {
        emit(name);
    }
    for name in HANDOFF_GIT_NAMES {
        emit(name);
    }
}

/// Escape a literal string for use inside a Seatbelt `(regex #"...")`. Escapes
/// both regex metacharacters and the `"` / `\` that would break the SBPL string.
fn regex_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            // Regex metacharacters.
            '.' | '^' | '$' | '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            // Would terminate the SBPL #"..." string literal.
            '"' => {
                out.push('\\');
                out.push('"');
            }
            _ => out.push(c),
        }
    }
    out
}

/// Canonicalize a path, resolving symlinks, even when the path does not exist
/// yet: walk up to the nearest existing ancestor, canonicalize that, and reattach
/// the remaining components. Seatbelt matches real paths, so a rule under a
/// symlinked root (e.g. /tmp -> /private/tmp) must be resolved or it will not
/// match. Falls back to the original path if nothing resolves.
fn canonical_best_effort(path: &Path) -> PathBuf {
    if let Ok(c) = path.canonicalize() {
        return c;
    }
    let mut suffix: Vec<std::ffi::OsString> = Vec::new();
    let mut cur = path;
    while let Some(parent) = cur.parent() {
        if let Some(name) = cur.file_name() {
            suffix.push(name.to_owned());
        }
        if let Ok(c) = parent.canonicalize() {
            let mut out = c;
            for s in suffix.iter().rev() {
                out.push(s);
            }
            return out;
        }
        cur = parent;
    }
    path.to_path_buf()
}

/// Insert `(with message "<tag>")` into every `deny` rule of a compiled profile,
/// including `(deny default)`. Done as a post-pass over lines so every deny —
/// however it was emitted — is tagged uniformly. Each deny is a single line that
/// ends in `)`, so we splice the message in just before that closing paren,
/// where it becomes a sibling clause of the rule's filter. The tag is
/// `[A-Za-z0-9_+/=]` only, so it needs no SBPL string escaping.
fn tag_deny_rules(profile: &str, tag: &str) -> String {
    let suffix = format!(" (with message \"{tag}\")");
    let mut out = String::with_capacity(profile.len() + profile.len() / 8);
    for line in profile.lines() {
        if line.trim_start().starts_with("(deny ") && line.ends_with(')') {
            let pos = line.rfind(')').unwrap(); // the rule's closing paren
            out.push_str(&line[..pos]);
            out.push_str(&suffix);
            out.push_str(&line[pos..]);
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

/// Build the per-run Seatbelt log tag for a command, matching sandbox-runtime's
/// `generateLogTag`: `CMD64_<base64 of the first 100 chars of the shell line>`
/// `_END__<9 random [a-z0-9]>_SBX`. The random suffix (one `_` before it)
/// separates this run from any other sandbox on the machine.
fn log_tag(command: &[String]) -> String {
    let line = shell_line(command);
    let first100: String = line.chars().take(100).collect();
    format!("CMD64_{}_END__{}_SBX", base64_encode(first100.as_bytes()), rand9())
}

/// Render argv as a shell line: each word verbatim when it is made only of safe
/// characters, otherwise single-quoted (POSIX `shlex.quote` rules), so a
/// `shellSplit` of the decoded line yields the original argv.
fn shell_line(command: &[String]) -> String {
    command.iter().map(|w| shell_quote(w)).collect::<Vec<_>>().join(" ")
}

fn shell_quote(w: &str) -> String {
    let safe = !w.is_empty()
        && w.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'_' | b'@' | b'%' | b'+' | b'=' | b':' | b',' | b'.' | b'/' | b'-')
        });
    if safe {
        w.to_string()
    } else {
        // Wrap in single quotes; close/escape/reopen for any embedded single quote.
        format!("'{}'", w.replace('\'', "'\"'\"'"))
    }
}

/// Standard base64 (RFC 4648, with `=` padding). No external crate — the backends
/// are std-only.
fn base64_encode(input: &[u8]) -> String {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        out.push(ALPHA[((n >> 18) & 63) as usize] as char);
        out.push(ALPHA[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { ALPHA[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHA[(n & 63) as usize] as char } else { '=' });
    }
    out
}

/// Nine random chars from `[a-z0-9]`. Not cryptographic — just unique enough to
/// tell this run apart from any other sandbox on the machine. Seeded from the
/// clock and pid, advanced with xorshift64.
fn rand9() -> String {
    const SYM: &[u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut s = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E3779B97F4A7C15)
        ^ ((std::process::id() as u64) << 32)
        | 1;
    let mut out = String::with_capacity(9);
    for _ in 0..9 {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        out.push(SYM[(s % 36) as usize] as char);
    }
    out
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
        // kern.proc* must never be ALLOWED (it leaks other processes' args/env/list).
        // It may appear in a deny rule — that is the protection, not a violation.
        assert!(
            !prof.contains("(allow sysctl-read (sysctl-name-prefix \"kern.proc"),
            "must never allow kern.proc.*"
        );
        assert!(
            prof.contains("(deny sysctl-read (sysctl-name-prefix \"kern.proc\"))"),
            "kern.proc must be explicitly denied"
        );
        // the deny for the hooks dir appears after the writable-root allow
        let allow_at = prof.find("(allow file-write* (subpath \"/work\"))").unwrap();
        let deny_at = prof.find("(deny file-write* (subpath \"/work/nested/.git/hooks\"))").unwrap();
        assert!(deny_at > allow_at, "denies must come after allows (last match wins)");
        // ancestor move-blocking present
        assert!(prof.contains("(deny file-write-unlink (literal \"/work/nested/.git\"))"));
        assert!(prof.contains("(deny file-write-unlink (literal \"/work/nested\"))"));
    }

    #[test]
    fn read_deny_inside_a_read_allow_wins_by_specificity() {
        // deny a dir, re-allow a branch, deny a deeper path inside the branch.
        // Seatbelt is last-match-wins, so the compiled rules must appear in
        // specificity order (least → most) and the deepest deny must come LAST.
        // (Nonexistent paths canonicalize to themselves, so this is pure string
        // order — no filesystem dependency.)
        let policy = Policy {
            writable_roots: vec![PathBuf::from("/work")],
            read_denies: vec![
                PathBuf::from("/vault/runs"),
                PathBuf::from("/vault/runs/mine/settings.json"),
            ],
            read_allows: vec![PathBuf::from("/vault/runs/mine")],
            ..Default::default()
        };
        let prof = compile_profile(&policy);
        let deny_runs = prof.find("(deny file-read* (subpath \"/vault/runs\"))").unwrap();
        let allow_mine = prof.find("(allow file-read* (subpath \"/vault/runs/mine\"))").unwrap();
        let deny_settings =
            prof.find("(deny file-read* (subpath \"/vault/runs/mine/settings.json\"))").unwrap();
        assert!(deny_runs < allow_mine, "re-allow must come after the broad deny");
        assert!(
            allow_mine < deny_settings,
            "the deeper deny must come after the re-allow so it wins (specificity)"
        );
    }

    #[test]
    fn log_tag_format_and_deny_tagging() {
        // Shell line + base64, matching sandbox-runtime's generateLogTag shape.
        let cmd = vec!["sh".to_string(), "-c".to_string(), "echo x > /tmp/ws/.git/hooks/pre-commit".to_string()];
        let line = shell_line(&cmd);
        assert_eq!(line, "sh -c 'echo x > /tmp/ws/.git/hooks/pre-commit'", "shell line quoting");
        let tag = log_tag(&cmd);
        assert!(tag.starts_with("CMD64_"), "tag: {tag}");
        assert!(tag.ends_with("_SBX"), "tag: {tag}");
        let b64 = tag.strip_prefix("CMD64_").unwrap().split("_END__").next().unwrap();
        // The random suffix is 9 chars of [a-z0-9] after exactly one extra '_'.
        let rand = tag.strip_suffix("_SBX").unwrap().rsplit("_END__").next().unwrap();
        assert_eq!(rand.len(), 9, "random suffix length: {rand}");
        assert!(rand.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()), "random charset: {rand}");
        // Decoding the base64 must give the shell line (first 100 chars).
        assert_eq!(base64_roundtrip(b64), &line[..line.len().min(100)]);

        // Every deny in a tagged profile carries the message; allows do not.
        let policy = Policy {
            writable_roots: vec![PathBuf::from("/work")],
            network: Some(Network::Denied),
            ..Default::default()
        };
        let tagged = compile_profile_tagged(&policy, Some(&tag));
        for l in tagged.lines() {
            if l.trim_start().starts_with("(deny ") {
                assert!(l.contains(&format!("(with message \"{tag}\")")), "deny not tagged: {l}");
            }
            if l.trim_start().starts_with("(allow ") {
                assert!(!l.contains("with message"), "allow should not be tagged: {l}");
            }
        }
        assert!(tagged.contains("(deny default (with message"), "default must be tagged");
        // Untagged profile is unchanged.
        assert!(!compile_profile(&policy).contains("with message"));
    }

    // Decode standard base64 back to a String (test helper).
    fn base64_roundtrip(s: &str) -> String {
        const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut bits = 0u32;
        let mut nbits = 0;
        let mut out = Vec::new();
        for c in s.bytes() {
            if c == b'=' { break; }
            let v = ALPHA.iter().position(|&a| a == c).unwrap() as u32;
            bits = (bits << 6) | v;
            nbits += 6;
            if nbits >= 8 {
                nbits -= 8;
                out.push((bits >> nbits) as u8);
            }
        }
        String::from_utf8(out).unwrap()
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
