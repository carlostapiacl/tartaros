//! tartaros-core — the policy model and backend interface.
//!
//! This crate is the differentiator: it defines *what* tartaros enforces
//! (the policy, including the trust-handoff set), independent of *how* a given
//! OS enforces it (the backends). Backends are swappable; the policy is not.

#[cfg(unix)]
pub mod signals;

use std::path::PathBuf;
#[cfg(test)]
use std::path::Path;
use std::time::Duration;

pub mod catalog;
pub mod effect;
mod backend;
mod compile;
mod env;
mod handoff;
mod paths;
mod profile;
pub use backend::*;
pub use env::*;
pub use handoff::*;
pub use paths::*;
pub use profile::*;
pub use effect::{
    Axis, Collector, DiscardSink, Direction, EffectEvent, EffectSink, FilterSink, JsonlSink, OtlpSink,
    Outcome, RecordMode, TraceContext, VecSink,
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

/// A glob deny (e.g. `~/.codex/*.config.toml`, `<repo>/**/.claude`): `*`/`?`
/// within one path segment, `**` for any number of segments. Only the macOS
/// Seatbelt backend can enforce a pattern as such (an anchored regex); the
/// Linux/seccomp+Landlock backend matches by inode, so a non-empty list is a
/// policy error there (surfaced by the CLI). On Linux an any-depth pattern with a
/// literal suffix is expanded to concrete paths instead (`any_depth_denies`).
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
    /// CONNECT only: a port grant never lets the agent listen (see `listen_ports`).
    pub local_ports: Vec<u16>,
    /// Ports the agent may LISTEN on (bind + accept), and connect to, for a test
    /// suite that starts its own server. Opt-in and separate from `local_ports`,
    /// because a listener is an inbound channel. Neither kernel filter scopes the
    /// address: on macOS a bind to `0.0.0.0:N` is reachable from the LAN; on Linux
    /// a listen grant alone keeps the run's private network namespace when the
    /// host offers one, so the listener is reachable only from inside the run
    /// (docs/limits.md).
    pub listen_ports: Vec<u16>,
    /// `--listen any`: bind, accept and connect on ANY TCP port, the ephemeral
    /// port 0 included, for test suites that pick their own port. Linux only, and
    /// only when the run has its own empty network namespace (no --net, --port,
    /// --allow-domain or egress namespace; root or user namespaces), where the
    /// only reachable address is the run's own loopback. Refused anywhere else:
    /// Seatbelt and Landlock scope ports, not addresses, so outside a private
    /// namespace "any port" would open every port to the LAN.
    pub listen_any: bool,
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
    /// Deny reads of processes outside this sandbox: Linux `/proc/<pid>`. On
    /// macOS it narrows `process-info*` to the agent itself, but no Seatbelt rule
    /// denies `KERN_PROCARGS2`: other processes' arguments, and the environment of
    /// any binary not Apple's own, stay readable (docs/broker.md).
    pub isolate_process_info: bool,
    /// Opt-in (P1-2 mitigation): before launch, create empty read-only
    /// placeholders for ABSENT top-level trust-handoff config files under the
    /// writable roots, so the agent cannot create a new one that a trusted tool
    /// later runs. Landlock protects by inode, so a path must exist to be carved;
    /// this materializes it. A workspace side effect — hence opt-in.
    pub materialize_absent_handoff: bool,
    /// Directories inside a writable root where the trust-handoff set is NOT
    /// protected: dependency trees a setup phase fills (`vendor/`, `node_modules/`)
    /// whose packages ship their own `.gitattributes`, `.github/` or `.git/`. An
    /// explicit, listed exemption (see [`Policy::check_handoff_exempt`]); every
    /// other rule still holds inside, and the repo's own surfaces stay protected.
    pub handoff_exempt: Vec<PathBuf>,
    /// Names of the trust-handoff config set (`HANDOFF_CONFIG_NAMES`) that are NOT
    /// protected in this run: `.goose` for a repo where the agent writes goose
    /// recipes, `.vscode` for one where it edits the editor config. Opt-in, one
    /// name at a time, and only names of that list: an unknown name is refused
    /// (a typo must not read as a protection that holds), and the git surfaces
    /// (`.git/hooks`, `.git/config`) cannot be opened this way — `handoff_scratch`
    /// and `handoff_exempt` scope that to one directory. See
    /// [`Policy::check_handoff_exempt`] and [`Policy::handoff_config_names`].
    pub handoff_allow: Vec<String>,
    /// Writable roots that are discarded after the run (a run's own TMPDIR), where
    /// the trust-handoff set is NOT protected. Each must BE a writable root:
    /// `handoff_exempt` refuses a root on purpose, because a root is usually the
    /// repo, but a scratch root has no later reader for a planted hook to reach —
    /// and the tests an agent runs there create `.git/hooks`, `conftest.py` and
    /// `.github/` by the thousand (measured: 2,881 denials of pytest's own temp
    /// tree in one fleet's baseline, 2026-11-24). See [`Policy::check_handoff_exempt`]
    /// for what a scratch root may not be.
    pub handoff_scratch: Vec<PathBuf>,
    /// Opt-in: also protect the per-user home-handoff surface
    /// (`HANDOFF_HOME_NAMES`: shell rc files, `.gitconfig`, `.ripgreprc`) under the
    /// writable roots, denied even if absent. Off by default because it breaks
    /// editing one's own dotfiles in the box; turn it on when the workspace is not
    /// a dotfiles repo and that surface is in scope.
    pub protect_home_handoff: bool,
    /// Security bench only (`--mutate`, feature `mutation-testing`): drop the
    /// whole trust-handoff set, to prove the corpus notices. Not in a normal build.
    #[cfg(feature = "mutation-testing")]
    #[doc(hidden)]
    pub mutation_drop_trust_handoff: bool,
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
    /// Any-depth write denies for a backend that matches by inode: the pattern's
    /// literal base (resolved) and the whole pattern. `any_depth_rules` turns
    /// them into concrete denies on every existing match; an absent one is held
    /// where the trust-handoff set holds that name (the CLI accepts no other),
    /// with the same limit for a new one in a subdirectory (docs/limits.md).
    pub any_depth_denies: Vec<(PathBuf, String)>,
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
    /// non-empty list (Mach is a macOS primitive). A non-empty `allow_mach_lookup`
    /// closes the otherwise broad mach-lookup down to a curated base of essential
    /// system services (sandbox-runtime's) PLUS these prefixes — additive, the same
    /// meaning the field has in sandbox-runtime settings.
    pub allow_mach_lookup: Vec<String>,
    pub allow_mach_register: Vec<String>,
    /// macOS-only: with a non-empty `allow_mach_lookup`, drop the curated base and
    /// open ONLY the listed prefixes (strict deny-by-default). Off by default because
    /// it breaks ordinary tools (the keychain, user/group lookups, notifications).
    pub mach_lookup_only: bool,
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
    /// Variables set LAST, over the allowlist, `inherit_env` and
    /// `env_passthrough` alike: what the supervisor decides the agent sees, not
    /// what the launcher had. A masked credential's sentinel goes here, so the
    /// real value in the launcher's environment never reaches the agent, even
    /// under `inherit_env`; so do the trust-store variables of its CA.
    pub env_set: Vec<(String, String)>,
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

#[cfg(test)]
mod tests;
