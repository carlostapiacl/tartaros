//! tartaros-core — the policy model and backend interface.
//!
//! This crate is the differentiator: it defines *what* tartaros enforces
//! (the policy, including the trust-handoff set), independent of *how* a given
//! OS enforces it (the backends). Backends are swappable; the policy is not.

use std::path::{Path, PathBuf};
use std::time::Duration;

pub mod catalog;
pub mod effect;
pub use effect::{
    Axis, Collector, Direction, EffectEvent, EffectSink, FilterSink, JsonlSink, Outcome,
    RecordMode, VecSink,
};

/// What a confined process may do with a filesystem path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
    /// Deny wins over any overlapping allow.
    Deny,
}

/// One filesystem rule. A `Deny` over a path that falls inside a broader
/// `Write` is the carve-out the other sandboxes handle poorly (Landlock cannot
/// express it at all; Seatbelt/bwrap need ancestor protection to be safe).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsRule {
    pub path: PathBuf,
    pub access: Access,
    /// Apply to this path even if it does not exist yet (a deny must hold for a
    /// path the agent may still create).
    pub even_if_absent: bool,
}

/// A single-segment glob deny (e.g. `~/.codex/*.config.toml`): `*`/`?` within
/// ONE path segment, no `**`. Only the macOS Seatbelt backend can enforce this
/// (as an anchored regex); the Linux/seccomp+Landlock backend matches by inode
/// and cannot, so a non-empty list is a policy error there (surfaced by the CLI).
#[derive(Debug, Clone)]
pub struct GlobDeny {
    /// The expanded pattern (absolute path with glob metacharacters).
    pub pattern: String,
    pub read: bool,
    pub write: bool,
}

/// Whether the confined process may reach the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Denied,
    /// Only the given loopback proxy port.
    ProxyOnly(u16),
    Allowed,
}

/// Files a *trusted tool outside the sandbox* later runs, loads, or scans,
/// expressed relative to a directory. These are the real escape surface.
///
/// `.git/hooks` and `.git/config` are handled separately, per git repo found,
/// so they protect nested repos too.
pub const HANDOFF_CONFIG_NAMES: &[&str] = &[
    // Agent/MCP config a trusted agent later loads and ACTS ON (launches an MCP
    // server, runs a slash-command, loads a skill/subagent) — passive RCE across
    // the trust boundary if the sandboxed agent can plant them.
    ".mcp.json",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".claude/commands",
    ".claude/agents",
    ".claude/skills",
    ".claude/hooks",
    // Codex CLI config/prompts a trusted Codex run later loads and acts on —
    // the same passive-RCE surface as .claude, protected as a whole directory.
    ".codex",
    // Editor auto-run surfaces: tasks/launch/extensions and workspace files a
    // trusted editor runs or trusts on open. Protected as whole directories, since
    // the auto-run surface is more than three JSON files (extensions.json,
    // *.code-workspace, .idea/runConfigurations, …).
    ".vscode",
    ".idea",
    // Git hooks relocated via core.hooksPath (Husky and friends).
    ".husky",
    // Git handoff beyond hooks/config: clean/smudge filters, submodule URLs.
    ".gitattributes",
    ".gitmodules",
    // Shell-into-the-repo and commit-time runners.
    ".envrc",
    ".pre-commit-config.yaml",
    // CI that a host runner later executes.
    ".github/workflows",
];

/// Within any git repository, the files a later `git` invocation executes or
/// reads from the host, outside the box.
pub const HANDOFF_GIT_NAMES: &[&str] = &[".git/hooks", ".git/config"];

/// Directory handoff surfaces, as path SUFFIXES. If a writable root is named
/// *inside* one of these (e.g. a root under `<repo>/.git/hooks/`), the downward
/// walk from that root never sees the enclosing surface, so it would be granted
/// wholesale — letting the agent plant a hook through a root nobody should have
/// put there. These suffixes let the policy detect that upward and deny the root.
/// Only directories a trusted tool later *runs from* are listed; `.git/objects`,
/// `.git/refs`, … are deliberately absent (a root there is legitimate).
pub const HANDOFF_DIR_SUFFIXES: &[&str] = &[
    ".git/hooks",
    ".claude/commands", ".claude/agents", ".claude/skills", ".claude/hooks",
    ".codex", ".vscode", ".idea", ".husky", ".github/workflows",
];

/// Per-USER startup/config files a trusted tool or the host's next shell later
/// runs or sources, when the workspace is (or becomes) HOME or a tool reads them
/// from the directory: shell rc files and per-user tool config with run-command
/// hooks (`.gitconfig` core.fsmonitor/core.pager, `.ripgreprc` pre-processor).
///
/// These are NOT in the default handoff set because protecting them breaks the
/// legitimate case of editing one's own dotfiles inside the sandbox (a dotfiles
/// repo is exactly a writable root full of these names). They are an OPT-IN:
/// `Policy::protect_home_handoff` adds them to the deny set, for when the
/// workspace is known not to be a dotfiles repo and the home-handoff surface is
/// in scope. Denied even if absent, like the config names.
pub const HANDOFF_HOME_NAMES: &[&str] = &[
    ".bashrc", ".bash_profile", ".zshrc", ".zprofile", ".profile",
    ".gitconfig", ".ripgreprc",
];

/// How deep the walk for nested markers goes. A real tree rarely nests repos
/// deeper than this; the bound keeps a pathological tree from stalling us.
/// Bound on the handoff-discovery walk (guards against pathological depth and
/// recursion blow-up). Real repositories are far shallower; a tree that exceeds
/// this is handled fail-safe (see `walk`) rather than silently left writable.
const MAX_WALK_DEPTH: usize = 64;

/// A complete, backend-independent confinement policy.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    /// Role label, used to attribute effect-log events. Optional.
    pub role: String,
    /// Roots the agent may write under.
    pub writable_roots: Vec<PathBuf>,
    /// Explicit filesystem rules; `Deny` always wins over an overlapping allow.
    pub fs_rules: Vec<FsRule>,
    pub network: Option<Network>,
    /// Specific loopback ports the role may reach (e.g. its app's 8001/8081/3307)
    /// without opening all of localhost. The field the field-use detected it needs.
    pub local_ports: Vec<u16>,
    /// External hosts (by IP) the role may reach; everything else is outside.
    pub allowed_hosts: Vec<String>,
    /// Egress allow-list BY DOMAIN NAME. Non-empty means: the agent gets no direct
    /// network; instead the CLI starts the capability broker on host loopback as a
    /// CONNECT/forward proxy restricted to these hosts (with SSRF defense), points
    /// the agent's HTTP(S)_PROXY at it, and grants only that one loopback port. An
    /// entry beginning with `.` (e.g. `.github.com`) matches the domain and its
    /// subdomains. This is a policy *intent*; the broker is the mechanism. Mutually
    /// exclusive with a fully isolated network namespace (which cannot reach the
    /// host-loopback broker).
    pub allow_domains: Vec<String>,
    /// Paths the agent may NOT read (secret dirs: `~/.ssh`, `~/.aws`, …). The
    /// enforcement counterpart of the secret collector.
    pub read_denies: Vec<PathBuf>,
    /// Paths to RE-ALLOW reading even though they sit inside a `read_denies`
    /// subtree: deny a broad directory but open one branch within it (e.g. deny
    /// the whole runs directory, allow this run's own files). Deny-inside-allow
    /// for reads, the mirror of the write carve.
    pub read_allows: Vec<PathBuf>,
    /// Deny any process-info / environment read of processes outside this
    /// sandbox (macOS `KERN_PROCARGS2`, Linux `/proc/<pid>`).
    pub isolate_process_info: bool,
    /// Opt-in (P1-2 mitigation): before launch, create empty read-only
    /// placeholders for ABSENT top-level trust-handoff config files under the
    /// writable roots, so the agent cannot create a new one that a trusted tool
    /// later runs. Landlock protects by inode, so a path must exist to be carved;
    /// this materializes it. A workspace side effect — hence opt-in.
    pub materialize_absent_handoff: bool,
    /// Opt-in: also protect the per-user home-handoff surface
    /// (`HANDOFF_HOME_NAMES`: shell rc files, `.gitconfig`, `.ripgreprc`) under the
    /// writable roots, denied even if absent. Off by default because it breaks
    /// editing one's own dotfiles in the box; turn it on when the workspace is not
    /// a dotfiles repo and that surface is in scope.
    pub protect_home_handoff: bool,
    /// Wall-clock limit; on expiry the whole process group is killed (exit 124).
    pub timeout: Option<Duration>,
    /// Address-space (memory) limit in bytes (`RLIMIT_AS`).
    pub max_memory_bytes: Option<u64>,
    /// Max processes for the user (`RLIMIT_NPROC`).
    pub max_processes: Option<u64>,
    /// CPU-time limit in seconds (`RLIMIT_CPU`).
    pub max_cpu_secs: Option<u64>,
    /// Opt-in (IPC-1): deny creating `AF_UNIX` sockets via seccomp, so the agent
    /// cannot reach a unix socket outside its territory (Landlock does not mediate
    /// pathname unix sockets). Default off — real agents use unix sockets, so this
    /// is a strict mode the policy turns on when that is acceptable.
    pub deny_unix_sockets: bool,
    /// Single-segment glob denies (e.g. `~/.codex/*.config.toml`). macOS-only
    /// (compiled to anchored Seatbelt regexes); the Linux backend rejects a
    /// non-empty list. Kept apart from `fs_rules` because they are patterns, not
    /// concrete inode paths.
    pub glob_denies: Vec<GlobDeny>,
    /// Specific AF_UNIX socket paths the agent MAY connect to. On macOS Seatbelt
    /// this is enforced per path (`remote unix-socket (path-literal …)`), so a
    /// single audit/IPC socket can be allowed while everything else stays denied.
    /// The Linux/seccomp backend cannot filter AF_UNIX by path (it is all-or-
    /// nothing), so a non-empty list there is a policy error, surfaced by the CLI.
    pub allow_unix_socket_paths: Vec<PathBuf>,
    /// macOS-only: Mach service name PREFIXES the agent may look up / register
    /// (`global-name-prefix`). Headless Chromium needs to REGISTER its
    /// `MachPortRendezvousServer.*` service at startup and its children look it up;
    /// without register it dies, without lookup the children loop. Scoped to a
    /// prefix — never a blanket `(allow mach-register)`. The Linux backend rejects a
    /// non-empty list (Mach is a macOS primitive). `allow_mach_lookup` is accepted
    /// for parity even though the base profile already allows mach-lookup broadly.
    pub allow_mach_lookup: Vec<String>,
    pub allow_mach_register: Vec<String>,
    /// macOS-only: directories under which the agent may BIND and CONNECT AF_UNIX
    /// sockets (`local`/`remote unix-socket (subpath …)`). Used by `--private-tmp`
    /// so a headless browser can publish its control socket in a run-private dir
    /// without opening all of `$TMPDIR` (where other runs' sockets live). On Linux
    /// AF_UNIX is governed all-or-nothing, so this is a no-op there (the dir is a
    /// writable root and AF_UNIX is already allowed unless `--deny-unix`).
    pub unix_socket_subpaths: Vec<PathBuf>,
    /// Opt-in: give the run its own private temp dir (exported as `TMPDIR`), made
    /// writable and scoped for AF_UNIX, so a browser's socket lands there and
    /// nowhere shared. The CLI creates it per run and tears it down after.
    pub private_tmp: bool,
    /// macOS-only: emit the minimal extra Seatbelt grants a headless Chromium/Chrome
    /// needs (POSIX shared memory for `apple.cfprefs.*` + the notification centre,
    /// POSIX semaphores, the IOSurface/RootDomain IOKit user clients, and
    /// `sysctl-read kern.proc.pid.` / `sysctl-write kern.tcsm_enable`). Scoped, not
    /// a blanket open. Without these the browser SIGSEGVs at startup. No effect on
    /// Linux.
    pub browser: bool,
    /// Environment the agent inherits. By DEFAULT the launcher's environment is
    /// scrubbed to a minimal safe allowlist (PATH/HOME/…): secrets commonly held
    /// in a launcher's env (AWS_*, *_TOKEN, …) are inherited at `exec` and are NOT
    /// governed by Landlock/Seatbelt, so passing them through would leak them to a
    /// possibly-compromised agent (and via `/proc/self/environ`). `env_passthrough`
    /// names vars to carry through (`KEY`) or set (`KEY=VALUE`); `inherit_env`
    /// restores full passthrough (opt into the leak, for trusted local use) minus
    /// the loader/interpreter injection vars (`LD_*`, `BASH_ENV`, …). The
    /// CLI applies this to the process environment before spawning.
    pub inherit_env: bool,
    pub env_passthrough: Vec<String>,
    /// Opt-in (Linux): run the agent in a private PID + mount namespace so it
    /// sees ONLY its own process subtree — it cannot enumerate, inspect
    /// (`/proc/<pid>/cmdline`) or signal host processes, and a fresh `/proc` is
    /// mounted to match. The agent becomes PID 1 of its namespace, which also
    /// tightens teardown (its death reaps the whole subtree). Needs
    /// CAP_SYS_ADMIN; fails closed if the namespace can't be created.
    pub isolate_pids: bool,
    /// Opt-in (Linux): run the agent in a private, empty network namespace with
    /// only loopback up — no external interface or route, so NO protocol can
    /// leave (TCP, UDP, ICMP, raw). This is the *complete* network-off: Landlock
    /// network rules only mediate TCP connect/bind, so UDP (DNS exfil) and ICMP
    /// still escape a Landlock-only deny. Mutually exclusive with granting egress
    /// (ports / broker on host loopback), since those need the host network.
    /// Needs CAP_SYS_ADMIN; fails closed.
    pub isolate_network: bool,
    /// Runtime-only (Linux, not from config): the name of a prepared network
    /// namespace the agent must join (`setns`) at spawn, for NET-01 egress scoping.
    /// The namespace has only a veth to the broker's host IP and NO default route,
    /// so the agent can reach the broker and nothing else. Set by the CLI after it
    /// builds the netns; the backend joins it in `pre_exec`. `None` = no scoped
    /// netns (ordinary host-network posture).
    pub egress_netns: Option<String>,
    /// Opt-in (Linux): install a seccomp filter that denies a curated set of
    /// dangerous, rarely-needed syscalls (kernel-module load, kexec, keyring,
    /// bpf, perf, ptrace, process_vm_*, mount/unshare/setns, reboot/time/swap).
    /// Shrinks the kernel attack surface — the surface the multi-tenant caveat is
    /// about — without blocking ordinary tools. Returns EPERM on a denied call.
    pub harden_syscalls: bool,
    /// Strict enforcement: every requested guarantee must actually be installed,
    /// or the launch ABORTS. In non-strict mode a cap that the host can't
    /// guarantee degrades (e.g. `--max-procs` to RLIMIT) with a warning; in
    /// strict mode that degradation is a hard error instead — "guaranteed or
    /// nothing". Set by the hostile-code / multi-tenant profiles and `--strict`.
    pub strict: bool,
}

impl Policy {
    /// The absent top-level trust-handoff config paths that
    /// `materialize_absent_handoff` would create (files, and dirs for the ones
    /// ending without an extension like `.github/workflows`).
    pub fn handoff_placeholders(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for root in &self.writable_roots {
            for name in HANDOFF_CONFIG_NAMES {
                let p = root.join(name);
                if !p.exists() {
                    out.push(p);
                }
            }
            if self.protect_home_handoff {
                for name in HANDOFF_HOME_NAMES {
                    let p = root.join(name);
                    if !p.exists() {
                        out.push(p);
                    }
                }
            }
        }
        out
    }
}

/// Env vars kept by default (F-13). Everything else in the launcher's environment
/// is dropped before the agent is spawned, because `exec` inheritance is NOT
/// governed by Landlock/Seatbelt and a launcher's env routinely holds secrets
/// (AWS_*, GITHUB_TOKEN, …) that would otherwise leak to the agent and via
/// `/proc/self/environ`. These are the vars ordinary tools need to run at all and
/// that carry no credential: path, home, identity, locale, shell, terminal, temp,
/// and the proxy vars the egress broker sets (proxy config is not a secret and the
/// agent needs it to reach the broker). `LC_*` is matched by prefix, not listed.
pub const ENV_ALLOWLIST: &[&str] = &[
    "PATH", "HOME", "USER", "LOGNAME", "SHELL", "LANG", "TERM", "TZ", "PWD",
    "TMPDIR", "TMP", "TEMP",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "all_proxy", "no_proxy",
];

/// Loader and interpreter injection vars: inherited, each one makes every child
/// the agent starts load or run code it names (a preload library, a startup
/// script, extra interpreter flags or module paths). Dropped even under
/// `inherit_env`. The list follows nono's `is_dangerous_env_var` (Apache-2.0).
pub const INJECTION_ENV_PREFIXES: &[&str] = &["LD_", "DYLD_", "BASH_FUNC_"];
pub const INJECTION_ENV_VARS: &[&str] = &[
    "BASH_ENV", "ENV", "CDPATH", "GLOBIGNORE", "PROMPT_COMMAND", "IFS",
    "PYTHONSTARTUP", "PYTHONPATH",
    "NODE_OPTIONS", "NODE_PATH",
    "PERL5OPT", "PERL5LIB",
    "RUBYOPT", "RUBYLIB", "GEM_PATH", "GEM_HOME",
    "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS",
    "DOTNET_STARTUP_HOOKS",
    "GOFLAGS",
];

pub fn is_injection_env_var(name: &str) -> bool {
    INJECTION_ENV_PREFIXES.iter().any(|p| name.starts_with(p)) || INJECTION_ENV_VARS.contains(&name)
}

impl Policy {
    /// Compute the exact environment the agent should be spawned with (F-13).
    ///
    /// By default the current process environment is filtered to
    /// [`ENV_ALLOWLIST`] (plus `LC_*`). With `inherit_env` the whole environment
    /// passes through (secrets and all, the caller opted in) EXCEPT the
    /// loader/interpreter injection vars of [`is_injection_env_var`]: those turn
    /// an inherited env into code execution in every child the agent starts, and
    /// no workflow needs them inherited silently. Then `env_passthrough` is
    /// applied — `KEY` carries the launcher's value through, `KEY=VALUE` sets it
    /// explicitly (overrides win over the allowlist, and naming an injection var
    /// there is explicit operator intent, so it is honoured). The backend applies
    /// the result with `env_clear()` + `envs(..)`, so enforcement does not depend
    /// on the CLI pre-scrubbing its own process env. Always `Some` today; the
    /// `Option` is kept for backends that may one day leave the env untouched.
    pub fn child_env(&self) -> Option<Vec<(String, String)>> {
        let original: Vec<(String, String)> = std::env::vars().collect();
        self.child_env_from(&original)
    }

    /// Pure core of [`child_env`]: given the launcher's environment `original`,
    /// compute the child's. Split out so the allowlist/passthrough logic is
    /// deterministically testable without touching the process environment.
    pub fn child_env_from(&self, original: &[(String, String)]) -> Option<Vec<(String, String)>> {
        let mut out: Vec<(String, String)> = original
            .iter()
            .filter(|(k, _)| {
                if self.inherit_env {
                    !is_injection_env_var(k)
                } else {
                    ENV_ALLOWLIST.contains(&k.as_str()) || k.starts_with("LC_")
                }
            })
            .cloned()
            .collect();
        let set = |out: &mut Vec<(String, String)>, k: &str, v: String| {
            if let Some(e) = out.iter_mut().find(|(ek, _)| ek == k) {
                e.1 = v;
            } else {
                out.push((k.to_string(), v));
            }
        };
        for entry in &self.env_passthrough {
            match entry.split_once('=') {
                Some((k, v)) => set(&mut out, k, v.to_string()),
                None => {
                    if let Some((_, v)) = original.iter().find(|(k, _)| k == entry) {
                        set(&mut out, entry, v.clone());
                    }
                }
            }
        }
        Some(out)
    }
}

impl Policy {
    /// Compile this policy's writable roots + denies into a Landlock-style
    /// **write allow-list**: a set of subtree roots the agent may write under,
    /// with every protected path carved out.
    ///
    /// Landlock cannot express "allow X but deny X/y" (nono refuses such a
    /// policy outright). TartarOS restructures instead: it grants the safe
    /// subtrees and excludes the branch that leads to each protected path. This
    /// is the TartarOS advantage on Linux.
    ///
    /// Tradeoff (honest): Landlock grants are hierarchical, so a directory that
    /// *contains* a protected path cannot itself be granted — the agent cannot
    /// create files **directly in** such a directory (its safe children are
    /// still fully writable). For paths where that matters, the Linux backend
    /// falls back to bwrap. `linux_write_allowlist` reports the allow set; the
    /// caller decides.
    pub fn linux_write_allowlist(&self) -> Vec<PathBuf> {
        // Explicit write denies are kept even when the path does not exist yet:
        // the carve then withholds the nearest existing ancestor (only its
        // existing children are granted), so the absent path cannot be created.
        // The implicit trust-handoff names are kept only where they exist; for
        // absent ones see the note below.
        let explicit: Vec<PathBuf> = self
            .fs_rules
            .iter()
            .filter(|r| r.access == Access::Deny)
            .map(|r| resolve_best_effort(&r.path))
            .collect();
        let mut denied: Vec<PathBuf> = self.trust_handoff_rules().into_iter().map(|r| r.path).collect();
        // Landlock protects by inode: a path that does not exist cannot be
        // carved out of an allow (and an absent name can still be created inside
        // a granted dir). So on Linux we only carve denies that EXIST; absent
        // trust-handoff files are a macOS/Seatbelt strength (regex denies cover
        // not-yet-existing paths) that Landlock cannot match. Without this an
        // empty writable root would be made fully unwritable by absent denies.
        // Landlock matches inodes, so carve on the REAL paths: a deny written
        // through a symlinked directory must exclude the directory it resolves to.
        denied = denied.iter().map(|p| resolve_best_effort(p)).collect();
        denied.retain(|p| p.exists());
        denied.extend(explicit);
        denied.sort();
        denied.dedup();

        let mut out = Vec::new();
        for root in &self.writable_roots {
            carve(&resolve_best_effort(root), &denied, &mut out);
        }
        out
    }

    /// Read allow-list for Linux: everything is readable except the `read_denies`
    /// (secret dirs), carved out of a read grant on `/`. Same inode caveat as the
    /// write carve — only existing paths are carved.
    pub fn linux_read_allowlist(&self) -> Vec<PathBuf> {
        let mut denied: Vec<PathBuf> = self.read_denies.clone();
        // Defense-in-depth for cross-process env reads (P1-3): exclude /proc from
        // the read grant so `/proc/<pid>/environ` of another process is not
        // readable. NOTE: the primary protection is the kernel — with Yama
        // `ptrace_scope >= 1` (Ubuntu default) an unrelated process's environ is
        // already blocked; this also covers `ptrace_scope = 0`. Measured: ordinary
        // tools (sh, cat, ls, curl, git, python3) still run with /proc excluded.
        if self.isolate_process_info {
            denied.push(PathBuf::from("/proc"));
        }
        // Carve on the real paths (Landlock matches inodes): a deny written through
        // a symlinked directory, or whose last component is a symlink, must hide
        // the file it resolves to, not just the name it was given.
        denied = denied.iter().map(|p| resolve_best_effort(p)).collect();
        denied.retain(|p| p.exists());
        let mut out = if denied.is_empty() {
            vec![PathBuf::from("/")]
        } else {
            denied.sort();
            denied.dedup();
            let mut o = Vec::new();
            carve(Path::new("/"), &denied, &mut o);
            o
        };
        // Re-allow explicit read_allows: a Landlock read grant on a subtree that
        // lies inside a denied parent re-permits exactly that branch — but a MORE
        // SPECIFIC deny inside that branch must stay denied (deny runs/ → allow
        // runs/mine/ → deny runs/mine/settings.json). A flat grant of the branch
        // would re-open the deeper secret (security bug). So we carve the
        // re-allowed subtree too, excluding any denies that fall within it. The
        // deepest rule wins, matching the macOS specificity order.
        for given in &self.read_allows {
            if !given.exists() {
                continue;
            }
            let a = &resolve_best_effort(given);
            // A re-allow only re-opens the branch it NAMES. If it reaches a denied
            // area only by following a symlink (the name itself is not inside any
            // deny), granting it would re-open a secret through a planted link.
            let named_inside = self.read_denies.iter().any(|d| given.starts_with(d) || given.starts_with(resolve_best_effort(d)));
            let lands_inside = denied.iter().any(|d| a.starts_with(d));
            if lands_inside && !named_inside {
                continue;
            }
            // Exact contradiction (the SAME path is both read-denied and
            // re-allowed): the deny wins, fail-safe. Equal depth is a tie, and a
            // security tool must resolve a tie to the more restrictive rule rather
            // than re-open the secret. Skip re-allowing it.
            if denied.iter().any(|d| d.as_path() == a.as_path()) {
                continue;
            }
            let inner: Vec<PathBuf> =
                denied.iter().filter(|d| d.starts_with(a) && d.as_path() != a.as_path()).cloned().collect();
            if inner.is_empty() {
                out.push(a.to_path_buf());
            } else {
                carve(a, &inner, &mut out);
            }
        }
        out
    }

    /// Resolved handoff surfaces (`hooks/`, `config`, submodule `modules/`) of any
    /// git repo whose `.git` is a POINTER FILE (`gitdir: <path>`) and whose target
    /// lands under a writable root. A regex/pattern deny can't express these: the
    /// target directory has no `.git` of its own and its name is arbitrary, so it
    /// is found only by reading the pointer. The macOS backend (pattern-based) adds
    /// these as literal denies; on Linux the walk already covers them.
    pub fn gitdir_pointer_handoff(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for r in self.trust_handoff_rules() {
            // trust_handoff_rules already resolves pointers; keep the deny paths
            // that fall under a writable root but are NOT under a `.git` directory
            // named in the tree (those are the pointer targets).
            let under_root = self
                .writable_roots
                .iter()
                .any(|w| r.path.starts_with(&resolve_best_effort(w)));
            let is_dotgit_path = r.path.components().any(|c| c.as_os_str() == ".git");
            if under_root && !is_dotgit_path {
                out.push(r.path);
            }
        }
        out.sort();
        out.dedup();
        out
    }

    /// Expand the trust-handoff set into concrete deny rules under every
    /// writable root, **at any depth** — this is what the measured competitors
    /// miss (they protect only the first level).
    ///
    /// For each git repository found (by a `.git` dir or file at any depth),
    /// `.git/hooks` and `.git/config` are denied, even if they do not exist yet.
    /// Top-level config handoff files are denied even if absent (the agent must
    /// not be able to create them); nested config handoff files are denied where
    /// they already exist.
    pub fn trust_handoff_rules(&self) -> Vec<FsRule> {
        let mut out = Vec::new();
        for root in &self.writable_roots {
            expand_root(root, self.protect_home_handoff, &mut out);
        }
        // Upward check: a writable root named INSIDE a handoff surface (e.g. under
        // `<repo>/.git/hooks/`) is denied wholesale — the downward walk can't see
        // the enclosing surface, so without this the root would be fully writable
        // and a hook could be planted through it. A sibling root under
        // `.git/objects` is untouched (not a handoff surface).
        for p in self.ancestor_handoff_denies() {
            out.push(deny(p, true));
        }
        dedup(&mut out);
        out
    }

    /// Writable roots that are named INSIDE a directory handoff surface
    /// (`<…>/.git/hooks/inner`, a root under `.vscode`, …). Such a root must not be
    /// granted writable — the downward walk from it never sees the enclosing
    /// surface. The macOS backend emits these as subpath denies; the Linux carve
    /// picks them up through [`trust_handoff_rules`]. Real (resolved) paths.
    pub fn ancestor_handoff_denies(&self) -> Vec<PathBuf> {
        self.writable_roots
            .iter()
            .filter(|r| root_inside_handoff_surface(r))
            .map(|r| resolve_best_effort(r))
            .collect()
    }
}

/// A named threat model: a baseline of confinement for a stated assumption about
/// the code being run. Explicit policy fields still override the baseline. The
/// point is honesty about what each tier does and does NOT guarantee — above all,
/// that TartarOS runs on a SHARED kernel, so no profile short of a microVM backend
/// provides true multi-tenant isolation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// The agent is trusted but fallible: confine mistakes and the trust-handoff
    /// set. Network default-deny, no namespace isolation. The everyday dev case.
    LocalAgent,
    /// The code may be actively malicious (single tenant): add PID isolation, an
    /// AF_UNIX lockdown and /proc isolation on top of local-agent. Still a shared
    /// kernel — a kernel exploit is out of scope for this tier.
    HostileCode,
    /// Untrusted multi-tenant workloads. TartarOS applies maximum single-kernel
    /// hardening (hostile-code + a fully isolated, egress-free network namespace)
    /// but does NOT provide kernel-level tenant isolation: a kernel LPE crosses
    /// the boundary. Real tenant separation needs a microVM backend
    /// (Firecracker/Kata), which is not implemented. Fail honest, not silent.
    MultiTenant,
}

impl Profile {
    pub fn parse(s: &str) -> Option<Profile> {
        match s {
            "local-agent" => Some(Profile::LocalAgent),
            "hostile-code" => Some(Profile::HostileCode),
            "multi-tenant" => Some(Profile::MultiTenant),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Profile::LocalAgent => "local-agent",
            Profile::HostileCode => "hostile-code",
            Profile::MultiTenant => "multi-tenant",
        }
    }

    /// Apply the profile's baseline to a policy. Only tightens; never grants.
    /// Call this BEFORE applying explicit flags so the operator can still relax
    /// or extend it. Network stays default-denied in every profile.
    pub fn apply(self, p: &mut Policy) {
        if p.network.is_none() {
            p.network = Some(Network::Denied);
        }
        match self {
            Profile::LocalAgent => {}
            // isolate_pids already gives the agent a /proc that shows only its own
            // namespace, so host processes/env are invisible — stronger than the
            // Landlock /proc read-deny (isolate_process_info), and it keeps the
            // agent's own /proc/self readable. It fails closed if namespaces are
            // unavailable, so there is no silent fallback to drop to.
            Profile::HostileCode => {
                p.isolate_pids = true;
                p.deny_unix_sockets = true;
                p.harden_syscalls = true;
                p.strict = true;
            }
            Profile::MultiTenant => {
                p.isolate_pids = true;
                p.deny_unix_sockets = true;
                p.isolate_network = true;
                p.harden_syscalls = true;
                p.strict = true;
            }
        }
    }

    /// One-line statement of what this tier confines.
    pub fn tier(self) -> &'static str {
        match self {
            Profile::LocalAgent => "confines a trusted-but-fallible agent (mistakes + trust-handoff)",
            Profile::HostileCode => "confines actively-malicious code on a single, shared kernel",
            Profile::MultiTenant => "maximum single-kernel hardening — NOT kernel-isolated",
        }
    }

    /// An honest caveat printed on run and in `explain`, or `None` when the tier's
    /// guarantee needs no asterisk. Never lets a tier overclaim.
    pub fn caveat(self) -> Option<&'static str> {
        match self {
            Profile::LocalAgent => None,
            Profile::HostileCode => Some(
                "shared kernel: a kernel-level exploit (LPE) can still cross this boundary. \
                 For untrusted multi-tenant workloads a microVM backend is required.",
            ),
            Profile::MultiTenant => Some(
                "multi-tenant KERNEL ISOLATION IS NOT PROVIDED. TartarOS confines via \
                 Landlock/seccomp/namespaces on a SHARED kernel; a kernel exploit crosses \
                 tenants. Real tenant separation requires a microVM backend \
                 (Firecracker/Kata), not yet implemented. This profile applies maximum \
                 single-kernel hardening ONLY.",
            ),
        }
    }
}

/// Resolve a path's symlinks the way the kernel would when the path is used,
/// including links whose target does not exist yet (a write through a dangling
/// link creates the target, so a rule on the link must land on the target).
/// Walks component by component: each existing symlink is replaced by its
/// target (relative targets resolve from the link's directory, and a `..` in a
/// target is taken from where the previous link led), while missing components
/// are appended as written. Bounded to 40 link hops, like the kernel.
pub fn resolve_best_effort(path: &Path) -> PathBuf {
    use std::collections::VecDeque;
    use std::path::Component;
    let mut out = if path.is_absolute() {
        PathBuf::from("/")
    } else {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"))
    };
    let mut pending: VecDeque<std::ffi::OsString> = VecDeque::new();
    let push_all = |p: &Path, q: &mut VecDeque<std::ffi::OsString>, front: bool| {
        let comps: Vec<std::ffi::OsString> = p
            .components()
            .filter_map(|c| match c {
                Component::Normal(n) => Some(n.to_owned()),
                Component::ParentDir => Some("..".into()),
                _ => None,
            })
            .collect();
        if front {
            for c in comps.into_iter().rev() {
                q.push_front(c);
            }
        } else {
            q.extend(comps);
        }
    };
    push_all(path, &mut pending, false);
    let mut hops = 0;
    while let Some(c) = pending.pop_front() {
        if c == ".." {
            out.pop();
            continue;
        }
        let cand = out.join(&c);
        match std::fs::symlink_metadata(&cand) {
            Ok(m) if m.file_type().is_symlink() && hops < 40 => {
                hops += 1;
                match std::fs::read_link(&cand) {
                    Ok(target) => {
                        if target.is_absolute() {
                            out = PathBuf::from("/");
                        }
                        push_all(&target, &mut pending, true);
                    }
                    Err(_) => out = cand,
                }
            }
            _ => out = cand,
        }
    }
    out
}

impl Policy {
    /// Explicit write denies whose (resolved) path does not exist yet. Landlock
    /// matches inodes, so these can only be enforced by the carve (withholding
    /// the nearest existing ancestor), never by a bind mount.
    pub fn absent_write_denies(&self) -> Vec<PathBuf> {
        self.fs_rules
            .iter()
            .filter(|r| r.access == Access::Deny)
            .map(|r| resolve_best_effort(&r.path))
            .filter(|p| std::fs::symlink_metadata(p).is_err())
            .collect()
    }

    /// A writable root that is a symlink grants its TARGET. Refuse one whose target
    /// is not inside another (non-symlink) writable root: following it would grant
    /// a directory nobody named (e.g. a link planted by an earlier run).
    pub fn check_symlinked_roots(&self) -> Result<(), String> {
        let plain: Vec<PathBuf> = self
            .writable_roots
            .iter()
            .filter(|r| !std::fs::symlink_metadata(r).map(|m| m.file_type().is_symlink()).unwrap_or(false))
            .map(|r| resolve_best_effort(r))
            .collect();
        for r in &self.writable_roots {
            let is_link = std::fs::symlink_metadata(r).map(|m| m.file_type().is_symlink()).unwrap_or(false);
            if is_link {
                let target = resolve_best_effort(r);
                if !plain.iter().any(|p| target.starts_with(p)) {
                    return Err(format!(
                        "writable root {} is a symlink to {}, which is outside the other writable roots; \
                         name the real directory instead",
                        r.display(),
                        target.display()
                    ));
                }
            }
        }
        Ok(())
    }
}

fn deny(path: PathBuf, even_if_absent: bool) -> FsRule {
    FsRule { path, access: Access::Deny, even_if_absent }
}

/// Is this writable root named inside a directory handoff surface? True when a
/// STRICT ancestor of the root (its real path) ends with one of
/// `HANDOFF_DIR_SUFFIXES` (`<…>/.git/hooks`, `<…>/.vscode`, …). The root itself
/// is not a surface — a root that *is* exactly `.git/hooks` is handled by the
/// downward walk; here we catch a root planted *below* one.
fn root_inside_handoff_surface(root: &Path) -> bool {
    let real = resolve_best_effort(root);
    let mut anc = real.parent();
    while let Some(a) = anc {
        if HANDOFF_DIR_SUFFIXES.iter().any(|suf| a.ends_with(suf)) {
            return true;
        }
        anc = a.parent();
    }
    false
}

/// Carve the Landlock write allow-list for one root (see
/// [`Policy::linux_write_allowlist`]).
fn carve(dir: &Path, denied: &[PathBuf], out: &mut Vec<PathBuf>) {
    // This dir is itself a protected path: grant nothing here.
    if denied.iter().any(|d| d == dir) {
        return;
    }
    // Does any protected path lie strictly under this dir?
    let has_denied_below = denied.iter().any(|d| d.starts_with(dir) && d != dir);
    if !has_denied_below {
        // Safe subtree: grant the whole thing.
        out.push(dir.to_path_buf());
        return;
    }
    // A protected path is below: cannot grant this dir wholesale. Recurse into
    // children, granting the safe ones and carving the unsafe branch. Files
    // directly in this dir are not granted (the documented tradeoff).
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.file_type().is_symlink() {
            // Never grant a symlink entry: the rule would be opened through the
            // link and land on its TARGET, which may be a denied path or lie
            // outside the territory. The target keeps whatever its own real path
            // is granted (reads and writes through the link check the target).
            continue;
        }
        if !meta.is_dir() {
            // A regular file here that is not itself denied stays writable.
            if !denied.iter().any(|d| d == &path) {
                out.push(path);
            }
            continue;
        }
        carve(&path, denied, out);
    }
}

fn expand_root(root: &Path, home: bool, out: &mut Vec<FsRule>) {
    // Top-level config handoff files: deny even if absent.
    for name in HANDOFF_CONFIG_NAMES {
        out.push(deny(root.join(name), true));
    }
    // Opt-in home-handoff names, same treatment (deny even if absent).
    if home {
        for name in HANDOFF_HOME_NAMES {
            out.push(deny(root.join(name), true));
        }
    }
    walk(root, 0, true, home, out);
}

/// Recursive walk. At each directory, protect a repo's git handoff files if the
/// directory is a git repo, and protect any config handoff files that exist.
fn walk(dir: &Path, depth: usize, is_root: bool, home: bool, out: &mut Vec<FsRule>) {
    if depth > MAX_WALK_DEPTH {
        // Fail-safe: beyond the discovery bound we cannot verify which
        // trust-handoff paths live below, so deny write to the whole subtree
        // instead of silently leaving it writable. The carve excludes it, so a
        // deep `.git/hooks` can never become writable just by being far down.
        out.push(deny(dir.to_path_buf(), true));
        return;
    }
    if is_git_repo(dir) {
        let dotgit = dir.join(".git");
        if dotgit.is_file() {
            // Worktree / submodule: `.git` is a FILE holding `gitdir: <path>`.
            // Rewriting it repoints the repo at attacker-controlled hooks, so deny
            // writing the pointer itself...
            out.push(deny(dotgit.clone(), true));
            // ...and follow the pointer: if the real gitdir falls under a writable
            // root, its hooks/config are a live handoff surface that nothing else
            // protects (that directory has no `.git` of its own, so the walk never
            // sees it as a repo). Deny them at the resolved location.
            if let Some(gitdir) = read_gitdir_pointer(&dotgit, dir) {
                out.push(deny(gitdir.join("hooks"), true));
                out.push(deny(gitdir.join("config"), true));
                deny_git_modules_handoff(&gitdir.join("modules"), 0, out);
            }
        } else {
            for name in HANDOFF_GIT_NAMES {
                out.push(deny(dir.join(name), true));
            }
            // Submodule gitdirs live under `.git/modules/<name>/…`; their hooks and
            // config are the same handoff surface. Deny those (leaving objects/refs
            // writable so submodule operations still work).
            deny_git_modules_handoff(&dotgit.join("modules"), 0, out);
        }
    }
    if !is_root {
        // Nested config-handoff names are denied even when absent, like the
        // top-level ones: the agent must not be able to CREATE one a trusted tool
        // later runs. (On Linux an absent nested path can only be withheld where a
        // mount namespace is unavailable — the carve covers it; the bind-mount
        // strategy and macOS regex both cover absent paths.)
        for name in HANDOFF_CONFIG_NAMES {
            out.push(deny(dir.join(name), true));
        }
        if home {
            for name in HANDOFF_HOME_NAMES {
                out.push(deny(dir.join(name), true));
            }
        }
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        // Do not follow symlinks (a symlink could point outside the root).
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !meta.is_dir() || meta.file_type().is_symlink() {
            continue;
        }
        // Never descend into a .git directory: its internals are already denied.
        if path.file_name().and_then(|n| n.to_str()) == Some(".git") {
            continue;
        }
        walk(&path, depth + 1, false, home, out);
    }
}

/// Read a `.git` pointer file (`gitdir: <path>`) and resolve it to an absolute,
/// symlink-resolved directory. A relative pointer is taken from the repo dir.
fn read_gitdir_pointer(dotgit: &Path, repo_dir: &Path) -> Option<PathBuf> {
    let text = std::fs::read_to_string(dotgit).ok()?;
    let rest = text.lines().find_map(|l| l.trim().strip_prefix("gitdir:"))?;
    let raw = PathBuf::from(rest.trim());
    let abs = if raw.is_absolute() { raw } else { repo_dir.join(raw) };
    Some(resolve_best_effort(&abs))
}

/// A git repo is a directory containing `.git` (a dir, or a file for submodules
/// and worktrees that reads `gitdir:`).
fn is_git_repo(dir: &Path) -> bool {
    let dotgit = dir.join(".git");
    dotgit.is_dir() || dotgit.is_file()
}

/// Deny the handoff surface (`hooks/`, `config`) of every submodule gitdir under a
/// repo's `.git/modules`, recursively (bounded) for nested submodules. Only these
/// two are denied, so a submodule's objects/refs stay writable and `git submodule`
/// operations keep working. Each entry directly under a `modules` dir is a
/// submodule gitdir; its own nested submodules live under its `modules`.
fn deny_git_modules_handoff(modules_dir: &Path, depth: usize, out: &mut Vec<FsRule>) {
    if depth > MAX_WALK_DEPTH {
        out.push(deny(modules_dir.to_path_buf(), true));
        return;
    }
    let entries = match std::fs::read_dir(modules_dir) {
        Ok(e) => e,
        Err(_) => return, // no .git/modules (no submodules) or unreadable
    };
    for entry in entries.flatten() {
        let gitdir = entry.path();
        let meta = match std::fs::symlink_metadata(&gitdir) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !meta.is_dir() || meta.file_type().is_symlink() {
            continue;
        }
        out.push(deny(gitdir.join("hooks"), true));
        out.push(deny(gitdir.join("config"), true));
        deny_git_modules_handoff(&gitdir.join("modules"), depth + 1, out);
    }
}

fn dedup(rules: &mut Vec<FsRule>) {
    rules.sort_by(|a, b| a.path.cmp(&b.path).then((a.access as u8).cmp(&(b.access as u8))));
    rules.dedup();
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn has_deny(rules: &[FsRule], p: &Path) -> bool {
        rules.iter().any(|r| r.access == Access::Deny && r.path == p)
    }

    fn get<'a>(env: &'a [(String, String)], k: &str) -> Option<&'a str> {
        env.iter().find(|(ek, _)| ek == k).map(|(_, v)| v.as_str())
    }

    #[test]
    fn child_env_scrubs_secrets_keeps_allowlist_by_default() {
        let launcher = vec![
            ("PATH".into(), "/usr/bin".into()),
            ("HOME".into(), "/home/a".into()),
            ("LC_ALL".into(), "C".into()),
            ("AWS_SECRET_ACCESS_KEY".into(), "leak".into()),
            ("GITHUB_TOKEN".into(), "leak2".into()),
        ];
        let p = Policy::default(); // inherit_env = false
        let env = p.child_env_from(&launcher).expect("should scrub, not inherit");
        // allowlisted + LC_* survive; the agent stays functional
        assert_eq!(get(&env, "PATH"), Some("/usr/bin"));
        assert_eq!(get(&env, "HOME"), Some("/home/a"));
        assert_eq!(get(&env, "LC_ALL"), Some("C"));
        // secrets are gone
        assert_eq!(get(&env, "AWS_SECRET_ACCESS_KEY"), None);
        assert_eq!(get(&env, "GITHUB_TOKEN"), None);
    }

    #[test]
    fn child_env_passthrough_and_explicit_set() {
        let launcher = vec![
            ("PATH".into(), "/usr/bin".into()),
            ("AWS_SECRET_ACCESS_KEY".into(), "from-launcher".into()),
        ];
        let p = Policy {
            // KEY carries the launcher's value through; KEY=VALUE sets explicitly;
            // a passthrough naming an absent var is a silent no-op.
            env_passthrough: vec![
                "AWS_SECRET_ACCESS_KEY".into(),
                "MY_FLAG=hello".into(),
                "NOT_PRESENT".into(),
            ],
            ..Default::default()
        };
        let env = p.child_env_from(&launcher).unwrap();
        assert_eq!(get(&env, "AWS_SECRET_ACCESS_KEY"), Some("from-launcher"));
        assert_eq!(get(&env, "MY_FLAG"), Some("hello"));
        assert_eq!(get(&env, "NOT_PRESENT"), None);
    }

    #[test]
    fn child_env_inherit_opts_into_full_passthrough() {
        let launcher = vec![("AWS_SECRET_ACCESS_KEY".into(), "leak".into())];
        let p = Policy { inherit_env: true, ..Default::default() };
        // inherit_env passes secrets through (the caller opted in)
        let env = p.child_env_from(&launcher).unwrap();
        assert_eq!(get(&env, "AWS_SECRET_ACCESS_KEY"), Some("leak"));
    }

    #[test]
    fn child_env_inherit_still_drops_loader_injection() {
        let launcher = vec![
            ("PATH".into(), "/usr/bin".into()),
            ("LD_PRELOAD".into(), "/evil.so".into()),
            ("DYLD_INSERT_LIBRARIES".into(), "/evil.dylib".into()),
            ("BASH_ENV".into(), "/evil.sh".into()),
            ("BASH_FUNC_ls%%".into(), "() { evil; }".into()),
            ("NODE_OPTIONS".into(), "--require /evil.js".into()),
            ("MY_APP_CONFIG".into(), "kept".into()),
        ];
        let p = Policy { inherit_env: true, ..Default::default() };
        let env = p.child_env_from(&launcher).unwrap();
        for k in ["LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "BASH_ENV", "BASH_FUNC_ls%%", "NODE_OPTIONS"] {
            assert_eq!(get(&env, k), None, "{k} must not be inherited");
        }
        assert_eq!(get(&env, "PATH"), Some("/usr/bin"));
        assert_eq!(get(&env, "MY_APP_CONFIG"), Some("kept"));
        // naming one explicitly is operator intent and is honoured
        let p = Policy { inherit_env: true, env_passthrough: vec!["NODE_OPTIONS".into()], ..Default::default() };
        let env = p.child_env_from(&launcher).unwrap();
        assert_eq!(get(&env, "NODE_OPTIONS"), Some("--require /evil.js"));
    }

    #[test]
    fn child_env_explicit_set_overrides_allowlist_value() {
        let launcher = vec![("PATH".into(), "/usr/bin".into())];
        let p = Policy { env_passthrough: vec!["PATH=/sandbox/bin".into()], ..Default::default() };
        let env = p.child_env_from(&launcher).unwrap();
        // the explicit --env PATH=... wins over the inherited allowlisted PATH,
        // and is not duplicated
        assert_eq!(get(&env, "PATH"), Some("/sandbox/bin"));
        assert_eq!(env.iter().filter(|(k, _)| k == "PATH").count(), 1);
    }

    #[test]
    fn protects_nested_git_hooks_at_any_depth() {
        let tmp = std::env::temp_dir().join(format!("sbx-th-{}", std::process::id()));
        let root = tmp.join("work");
        let nested = root.join("a").join("b").join("nested");
        fs::create_dir_all(nested.join(".git")).unwrap();
        fs::create_dir_all(root.join(".git")).unwrap();

        let policy = Policy { writable_roots: vec![root.clone()], ..Default::default() };
        let rules = policy.trust_handoff_rules();

        // top-level repo
        assert!(has_deny(&rules, &root.join(".git/hooks")));
        // deeply nested repo — the thing the others miss
        assert!(has_deny(&rules, &nested.join(".git/hooks")));
        assert!(has_deny(&rules, &nested.join(".git/config")));

        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn top_level_config_denied_even_if_absent() {
        let tmp = std::env::temp_dir().join(format!("sbx-cfg-{}", std::process::id()));
        let root = tmp.join("work");
        fs::create_dir_all(&root).unwrap();

        let policy = Policy { writable_roots: vec![root.clone()], ..Default::default() };
        let rules = policy.trust_handoff_rules();

        let settings = root.join(".claude/settings.json");
        assert!(!settings.exists());
        let r = rules.iter().find(|r| r.path == settings).expect("settings.json must be denied");
        assert_eq!(r.access, Access::Deny);
        assert!(r.even_if_absent);

        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn home_handoff_is_opt_in() {
        let tmp = std::env::temp_dir().join(format!("sbx-home-{}", std::process::id()));
        let root = tmp.join("work");
        fs::create_dir_all(&root).unwrap();
        let bashrc = root.join(".bashrc");
        let gitconfig = root.join(".gitconfig");

        // Default: home-handoff names are NOT denied (a dotfiles repo stays editable).
        let off = Policy { writable_roots: vec![root.clone()], ..Default::default() };
        let off_rules = off.trust_handoff_rules();
        assert!(!off_rules.iter().any(|r| r.path == bashrc), ".bashrc must be writable by default");
        assert!(!off_rules.iter().any(|r| r.path == gitconfig), ".gitconfig must be writable by default");

        // Opt-in: the same names are denied, even if absent.
        let on = Policy { writable_roots: vec![root.clone()], protect_home_handoff: true, ..Default::default() };
        let on_rules = on.trust_handoff_rules();
        let denied = |p: &Path| on_rules.iter().any(|r| r.path == *p && r.access == Access::Deny && r.even_if_absent);
        assert!(denied(&bashrc), ".bashrc must be denied under protect_home_handoff");
        assert!(denied(&gitconfig), ".gitconfig must be denied under protect_home_handoff");
        // A non-handoff file stays writable even with the flag on.
        assert!(!on_rules.iter().any(|r| r.path == root.join("src.rs")));

        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn writable_root_inside_handoff_surface_is_denied() {
        let tmp = std::env::temp_dir().join(format!("sbx-rih-{}", std::process::id()));
        // One root inside .git/hooks (a surface), a sibling under .git/objects (not).
        let inside = tmp.join("repo/.git/hooks/inner");
        let objects = tmp.join("repo/.git/objects");
        fs::create_dir_all(&inside).unwrap();
        fs::create_dir_all(&objects).unwrap();

        let policy = Policy {
            writable_roots: vec![inside.clone(), objects.clone()],
            ..Default::default()
        };
        let denied = policy.ancestor_handoff_denies();
        // The root beneath .git/hooks is denied; the one beneath .git/objects is not.
        assert!(denied.iter().any(|p| p == &resolve_best_effort(&inside)),
            "a root inside .git/hooks must be denied");
        assert!(!denied.iter().any(|p| p == &resolve_best_effort(&objects)),
            "a root inside .git/objects is legitimate and stays writable");

        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn linux_allowlist_carves_out_nested_git() {
        let tmp = std::env::temp_dir().join(format!("sbx-carve-{}", std::process::id()));
        let root = tmp.join("work");
        // work/src (safe), work/a/nested/.git (protected), work/a/other (safe)
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("a/nested/.git/hooks")).unwrap();
        fs::create_dir_all(root.join("a/nested/.git/objects")).unwrap();
        fs::create_dir_all(root.join("a/other")).unwrap();
        // The allow-list is on real paths (Landlock matches inodes); compare on them.
        let root = root.canonicalize().unwrap();

        let policy = Policy { writable_roots: vec![root.clone()], ..Default::default() };
        let allow = policy.linux_write_allowlist();

        let granted = |p: &Path| allow.iter().any(|a| p.starts_with(a));
        // safe subtrees are writable
        assert!(granted(&root.join("src/x")));
        assert!(granted(&root.join("a/other/y")));
        // git internals that are NOT handoff files stay writable (git needs them)
        assert!(granted(&root.join("a/nested/.git/objects/ab")));
        // the protected handoff dirs are NOT writable
        assert!(!granted(&root.join("a/nested/.git/hooks/pre-commit")));
        assert!(!granted(&root.join("a/nested/.git/config")));

        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn does_not_follow_symlinks_out_of_root() {
        // A symlinked dir inside root must not be walked (it could point out).
        let tmp = std::env::temp_dir().join(format!("sbx-sym-{}", std::process::id()));
        let root = tmp.join("work");
        let outside = tmp.join("outside");
        fs::create_dir_all(outside.join(".git")).unwrap();
        fs::create_dir_all(&root).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();

        let policy = Policy { writable_roots: vec![root.clone()], ..Default::default() };
        let rules = policy.trust_handoff_rules();
        // The symlinked outside repo's hooks must NOT appear.
        assert!(!has_deny(&rules, &root.join("link/.git/hooks")));

        fs::remove_dir_all(&tmp).ok();
    }

    /// Does the allow-list grant `x` (the backend grants PathBeneath per entry, so
    /// a path is allowed iff it is under or equal to a granted entry)?
    fn granted(allow: &[PathBuf], x: &Path) -> bool {
        allow.iter().any(|a| x.starts_with(a))
    }

    #[test]
    fn profiles_escalate_and_stay_honest() {
        // local-agent adds no namespace/IPC hardening and makes no claim to fix.
        let mut p = Policy::default();
        Profile::LocalAgent.apply(&mut p);
        assert!(!p.isolate_pids && !p.isolate_network && !p.deny_unix_sockets);
        assert!(Profile::LocalAgent.caveat().is_none());

        // hostile-code hides the host (PID ns) and locks down AF_UNIX, but keeps
        // the agent's own /proc readable (no blunt isolate_process_info).
        let mut h = Policy::default();
        Profile::HostileCode.apply(&mut h);
        assert!(h.isolate_pids && h.deny_unix_sockets && h.harden_syscalls && h.strict);
        assert!(!h.isolate_process_info, "isolate_pids supersedes the /proc read-deny");
        assert!(!h.isolate_network, "hostile-code is not offline by default");
        assert!(Profile::HostileCode.caveat().unwrap().contains("kernel"));

        // multi-tenant adds full egress-off AND must never claim kernel isolation.
        let mut m = Policy::default();
        Profile::MultiTenant.apply(&mut m);
        assert!(m.isolate_pids && m.deny_unix_sockets && m.isolate_network);
        let c = Profile::MultiTenant.caveat().unwrap();
        assert!(c.contains("NOT PROVIDED") && c.contains("microVM"));

        // profiles only tighten: an explicit network grant survives apply().
        let mut net = Policy { network: Some(Network::Allowed), ..Default::default() };
        Profile::HostileCode.apply(&mut net);
        assert_eq!(net.network, Some(Network::Allowed));

        assert_eq!(Profile::parse("hostile-code"), Some(Profile::HostileCode));
        assert_eq!(Profile::parse("nope"), None);
    }

    /// Monotonicity of the policy compiler: a MORE restrictive policy must never
    /// allow an operation a LESS restrictive one forbade —
    /// `P2 ⊆ P1 ⟹ Allowed(P2) ⊆ Allowed(P1)`. This is the invariant that a
    /// carve bug (e.g. P0-1: a deny that accidentally widened the grant) breaks.
    /// We check the two restriction axes of the write carve exhaustively on a
    /// fixed tree: (a) adding any deny, (b) shrinking the writable roots. The read
    /// carve uses the same `carve` primitive, rooted at `/`.
    #[test]
    fn compiler_is_monotone_under_restriction() {
        let tmp = std::env::temp_dir().join(format!("sbx-mono-{}", std::process::id()));
        let root = tmp.join("work");
        for d in ["a/sub/deep", "b", "c"] {
            fs::create_dir_all(root.join(d)).unwrap();
        }
        for f in ["top.txt", "a/f1.txt", "a/sub/f2.txt", "a/sub/deep/f3.txt", "b/f4.txt"] {
            fs::write(root.join(f), b"x").unwrap();
        }

        // Candidate paths probed for the Allowed set — existing and absent.
        let candidates: Vec<PathBuf> = [
            "top.txt", "a", "a/f1.txt", "a/sub", "a/sub/f2.txt", "a/sub/deep",
            "a/sub/deep/f3.txt", "b", "b/f4.txt", "c",
            "a/new.txt", "a/sub/new", "a/sub/deep/new.txt", "c/new", // absent
        ]
        .iter()
        .map(|p| root.join(p))
        .collect();

        // Deny universe: a mix of dirs and a file inside the tree.
        let universe: Vec<PathBuf> = ["a", "a/sub", "a/sub/deep", "b", "a/f1.txt"]
            .iter()
            .map(|p| root.join(p))
            .collect();

        let write_allow = |denied: &[PathBuf]| -> Vec<PathBuf> {
            let mut out = Vec::new();
            carve(&root, denied, &mut out);
            out
        };
        let allowed_set = |allow: &[PathBuf]| -> Vec<bool> {
            candidates.iter().map(|x| granted(allow, x)).collect()
        };

        // (a) Adding ANY single deny to ANY base deny-set only shrinks Allowed.
        // Single-element monotonicity implies it for arbitrary added sets.
        let n = universe.len();
        for mask in 0u32..(1 << n) {
            let base: Vec<PathBuf> =
                (0..n).filter(|i| mask & (1 << i) != 0).map(|i| universe[i].clone()).collect();
            let base_allowed = allowed_set(&write_allow(&base));
            for extra in &universe {
                if base.iter().any(|d| d == extra) {
                    continue;
                }
                let mut more = base.clone();
                more.push(extra.clone());
                let more_allowed = allowed_set(&write_allow(&more));
                for (i, x) in candidates.iter().enumerate() {
                    assert!(
                        !(more_allowed[i] && !base_allowed[i]),
                        "non-monotone: adding deny {} made {} writable (base denies {:?})",
                        extra.display(), x.display(), base
                    );
                }
            }
        }

        // (b) Shrinking the writable roots only shrinks Allowed.
        let p_big = Policy { writable_roots: vec![root.join("a"), root.join("b")], ..Default::default() };
        let p_small = Policy { writable_roots: vec![root.join("a")], ..Default::default() };
        let big = p_big.linux_write_allowlist();
        let small = p_small.linux_write_allowlist();
        for x in &candidates {
            assert!(
                !(granted(&small, x) && !granted(&big, x)),
                "non-monotone: dropping a writable root made {} writable",
                x.display()
            );
        }

        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn deep_subtree_beyond_walk_depth_is_not_writable() {
        // A trust-handoff path deeper than the discovery walk must NOT be left
        // writable — the walk denies the over-depth subtree fail-safe.
        let tmp = std::env::temp_dir().join(format!("sbx-deep-{}", std::process::id()));
        let root = tmp.join("work");
        let mut deep = root.clone();
        for _ in 0..(MAX_WALK_DEPTH + 3) {
            deep = deep.join("d");
        }
        fs::create_dir_all(&deep).unwrap();
        fs::write(root.join("shallow.txt"), b"x").unwrap();
        let (root, deep) = (root.canonicalize().unwrap(), deep.canonicalize().unwrap());

        let policy = Policy { writable_roots: vec![root.clone()], ..Default::default() };
        let allow = policy.linux_write_allowlist();
        let granted = |x: &Path| allow.iter().any(|a| x.starts_with(a));

        // shallow work stays writable...
        assert!(granted(&root.join("shallow.txt")), "shallow file must be writable");
        // ...but the over-depth subtree is denied (fail-safe), so a planted
        // .git/hooks that deep could never become writable.
        assert!(!granted(&deep.join(".git/hooks/pre-commit")), "deep subtree must not be writable");

        fs::remove_dir_all(&tmp).ok();
    }

    /// Randomized property test (fuzz) of the write carve over many random
    /// directory trees and random deny-sets. Asserts the two core invariants that
    /// a carve bug (the P0-1 class) would break:
    ///   SAFETY: no path equal-to-or-under any deny is ever granted — not even
    ///           via an accidentally-granted ancestor of the deny.
    ///   MONOTONICITY: adding one more deny never grants a path that was denied.
    /// Deterministic (fixed seed) so a failure reproduces; the tree, deny-set and
    /// offending path are printed.
    #[test]
    fn carve_fuzz_invariants() {
        // xorshift64 — a tiny deterministic PRNG, no external deps.
        let mut state: u64 = 0x9E3779B97F4A7C15;
        let mut rng = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        // Build a random tree under `dir` up to `depth`; collect every node path.
        fn build(dir: &Path, depth: u32, rng: &mut dyn FnMut() -> u64, nodes: &mut Vec<PathBuf>) {
            let n = (rng() % 4) as usize; // 0..=3 children
            for i in 0..n {
                let is_dir = depth > 0 && rng().is_multiple_of(2);
                let name = format!("{}{}", if is_dir { "d" } else { "f" }, i);
                let p = dir.join(&name);
                if is_dir {
                    let _ = fs::create_dir_all(&p);
                    nodes.push(p.clone());
                    build(&p, depth - 1, rng, nodes);
                } else {
                    let _ = fs::write(&p, b"x");
                    nodes.push(p);
                }
            }
        }

        for iter in 0..120 {
            let tmp = std::env::temp_dir().join(format!("sbx-fuzz-{}-{}", std::process::id(), iter));
            let root = tmp.join("work");
            fs::create_dir_all(&root).unwrap();
            let mut nodes = Vec::new();
            build(&root, 4, &mut rng, &mut nodes);
            if nodes.is_empty() {
                fs::remove_dir_all(&tmp).ok();
                continue;
            }

            // Random deny subset.
            let deny: Vec<PathBuf> =
                nodes.iter().filter(|_| rng() % 3 == 0).cloned().collect();
            let mut out = Vec::new();
            carve(&root, &deny, &mut out);

            // SAFETY: nothing at/under a deny may be granted.
            for d in &deny {
                for x in &nodes {
                    if x.starts_with(d) {
                        assert!(
                            !granted(&out, x),
                            "SAFETY broken (iter {iter}): {} granted though under deny {}",
                            x.display(), d.display()
                        );
                    }
                }
            }

            // MONOTONICITY: adding one more deny never newly grants anything.
            if let Some(extra) = nodes.iter().find(|n| !deny.contains(n)) {
                let mut deny2 = deny.clone();
                deny2.push(extra.clone());
                let mut out2 = Vec::new();
                carve(&root, &deny2, &mut out2);
                for x in &nodes {
                    assert!(
                        !(granted(&out2, x) && !granted(&out, x)),
                        "MONOTONICITY broken (iter {iter}): adding deny {} granted {}",
                        extra.display(), x.display()
                    );
                }
            }

            fs::remove_dir_all(&tmp).ok();
        }
    }

    #[test]
    #[cfg(target_os = "linux")] // carves the real "/" tree; Linux has real dirs
    fn read_allow_does_not_reopen_a_deeper_deny() {
        // Specificity rule: deny a dir, re-allow a branch within it, then deny a
        // deeper path inside that branch. The deeper deny must still win — a flat
        // re-allow of the branch would re-open the secret (the reported bug).
        let tmp = std::env::temp_dir().join(format!("sbx-readcarve-{}", std::process::id()));
        let runs = tmp.join("runs");
        let mine = runs.join("mine");
        fs::create_dir_all(&mine).unwrap();
        fs::write(mine.join("otro"), b"ok").unwrap();
        fs::write(mine.join("settings.json"), b"SECRET").unwrap();
        fs::write(runs.join("ajeno"), b"other").unwrap();

        let p = Policy {
            read_denies: vec![runs.clone(), mine.join("settings.json")],
            read_allows: vec![mine.clone()],
            ..Default::default()
        };
        let allow = p.linux_read_allowlist();

        // The re-allowed branch is readable...
        assert!(granted(&allow, &mine.join("otro")), "re-allowed branch must be readable");
        // ...but the deeper deny within it is NOT (security property)...
        assert!(
            !granted(&allow, &mine.join("settings.json")),
            "a deny inside a re-allow must stay denied, got reopened: {allow:?}"
        );
        // ...and a sibling under the original deny stays denied.
        assert!(!granted(&allow, &runs.join("ajeno")), "sibling under the deny stays denied");

        fs::remove_dir_all(&tmp).ok();
    }
}
