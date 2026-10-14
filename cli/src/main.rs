//! tartaros CLI — run a command confined by a policy, on the OS backend.
//!
//! Usage:
//!   tartaros run [options] -- <command> [args...]
//!
//! Options:
//!   --profile NAME         threat-model preset: local-agent | hostile-code | multi-tenant
//!   --role NAME            label for effect-log attribution
//!   --write DIR            a writable root (repeatable)
//!   --read-deny DIR        deny reads of this path (repeatable; secrets)
//!   --read-allow DIR       re-allow reading this path inside a read-deny (repeatable)
//!   --write-deny DIR       deny writes to this path inside a writable root (repeatable)
//!   --port N               allow loopback TCP to this port (repeatable)
//!   --allow-domain HOST    egress ONLY to this domain, via the capability broker
//!                          (CONNECT/HTTPS + SSRF defense); repeatable
//!   --net                  allow all network (default: denied)
//!   --deny-unix            deny AF_UNIX sockets (Linux, seccomp)
//!   --isolate-pids         run in a private PID+mount namespace (Linux; hides host processes)
//!   --isolate-net          run in an empty network namespace (Linux; no egress at all, loopback only)
//!   --seccomp-strict       deny dangerous syscalls to shrink kernel attack surface (Linux)
//!   --strict               a requested guarantee that cannot be installed aborts the run
//!   --materialize          pre-create absent trust-handoff placeholders (Linux)
//!   --private-tmp          run-private TMPDIR, AF_UNIX scoped to it (headless browsers)
//!   --env KEY[=VALUE]      carry one launcher var through, or set it (default: env is scrubbed)
//!   --inherit-env          inherit the full launcher env (opt into leaking secrets)
//!   --timeout SECS         kill the process group after SECS (exit 124)
//!   --max-mem BYTES        address-space limit
//!   --max-procs N          process limit
//!   --max-cpu SECS         total CPU-seconds limit (RLIMIT_CPU; root-proof)
//!   --log FILE             write the effect log (JSON Lines) here (Linux)
//!   --settings FILE        map a sandbox-runtime settings.json onto the generic
//!                          policy; refuses (exit 2) on anything it can't guarantee
//!
//! Exit code is the command's (128+signal on signal death, 124 on timeout).

use tartaros_core::{Access, FsRule, Network, Policy, Profile};
use serde::Deserialize;
use std::path::PathBuf;
use std::process::exit;
use std::time::Duration;

/// A policy file (TOML) — declare a role's confinement once, apply it on any OS.
/// Flags on the command line override / append to it.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    #[serde(default)]
    profile: Option<String>,
    #[serde(default)]
    role: String,
    #[serde(default)]
    writable_roots: Vec<String>,
    #[serde(default)]
    read_denies: Vec<String>,
    #[serde(default)]
    read_allows: Vec<String>,
    #[serde(default)]
    write_denies: Vec<String>,
    #[serde(default)]
    local_ports: Vec<u16>,
    #[serde(default)]
    net: bool,
    #[serde(default)]
    deny_unix_sockets: bool,
    #[serde(default)]
    isolate_pids: bool,
    #[serde(default)]
    isolate_network: bool,
    #[serde(default)]
    harden_syscalls: bool,
    #[serde(default)]
    strict: bool,
    #[serde(default)]
    materialize_absent_handoff: bool,
    #[serde(default)]
    isolate_process_info: bool,
    #[serde(default)]
    timeout_secs: Option<u64>,
    #[serde(default)]
    max_memory_bytes: Option<u64>,
    #[serde(default)]
    max_processes: Option<u64>,
    #[serde(default)]
    max_cpu_secs: Option<u64>,
}

/// Expand a leading `~` to $HOME so policy files are portable.
fn expand(s: &str) -> String {
    if let Some(rest) = s.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}/{rest}");
        }
    }
    s.to_string()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()) {
        Some("run") => cmd_run(&args[1..]),
        Some("explain") => cmd_explain(&args[1..]),
        Some("version" | "--version" | "-V") => {
            println!("tartaros {} ({})", env!("CARGO_PKG_VERSION"), backend_os());
            exit(0);
        }
        Some("help" | "--help" | "-h") | None => {
            print!("{HELP}");
            exit(if args.is_empty() { 2 } else { 0 });
        }
        Some(other) => {
            eprintln!("tartaros: unknown command `{other}`\n");
            print!("{HELP}");
            exit(2);
        }
    }
}

fn backend_os() -> &'static str {
    if cfg!(target_os = "linux") {
        "linux/landlock+seccomp+cgroup+ns"
    } else if cfg!(target_os = "macos") {
        "macos/seatbelt"
    } else {
        "unsupported"
    }
}

const HELP: &str = "\
TartarOS — secure agent runtime. NOTHING ESCAPES THE BOUNDARY.

USAGE:
  tartaros run [options] -- <command> [args...]   run a command confined by a policy
  tartaros explain [options]                      print what a policy grants, without running
  tartaros version                                print version and backend
  tartaros help                                   this help

PROFILE (preset threat model; flags still extend it):
  --profile local-agent|hostile-code|multi-tenant

POLICY:
  --config FILE          load a TOML policy (flags override it)
  --settings FILE        map a sandbox-runtime settings.json onto the generic
                         policy; refuses (exit 2) on anything it can't guarantee
  --role NAME            label for the effect log
  --write DIR            a writable root (repeatable)
  --read-deny DIR        deny reads of this path, e.g. a secret dir (repeatable)
  --read-allow DIR       re-allow reading this path inside a read-deny (repeatable)
  --write-deny DIR       deny writes to this path inside a writable root (repeatable)
  --port N               allow loopback TCP to this port (repeatable)
  --allow-domain HOST    egress ONLY to this domain through the broker (HTTPS via
                         CONNECT, SSRF-defended); .example.com matches subdomains
  --net                  allow all network (default: denied)

HARDENING (Linux; the hostile/multi-tenant profiles set these):
  --isolate-pids         private PID+mount namespace (hide host processes)
  --isolate-net          empty network namespace (no egress, any protocol)
  --seccomp-strict       deny dangerous syscalls (shrink kernel attack surface)
  --strict               a requested guarantee that cannot be installed aborts the run
  --deny-unix            deny AF_UNIX sockets
  --isolate-proc         deny reads of other processes' /proc
  --materialize          pre-create absent trust-handoff placeholders
  --private-tmp          run-private TMPDIR; AF_UNIX scoped to it (headless browsers)
  --browser              macOS: minimal extra Seatbelt grants for headless Chromium/Chrome

ENVIRONMENT (secrets in the launcher's env are NOT governed by Landlock/Seatbelt):
  (default)              scrub env to a safe allowlist (PATH/HOME/LANG/... + LC_*)
  --env KEY              carry one var through from the launcher's environment
  --env KEY=VALUE        set one var explicitly for the agent
  --inherit-env          FULL passthrough: inherit the launcher env, secrets and all

LIMITS:
  --timeout SECS         kill the run after SECS (exit 124)
  --max-mem BYTES        address-space / cgroup memory cap
  --max-procs N          process cap (cgroup pids.max; root-proof)
  --max-cpu SECS         total CPU-seconds cap

OBSERVABILITY:
  --log FILE             write the first-hand effect log (JSON Lines)

Exit code is the command's (128+signal on signal death, 124 on timeout).
";

fn cmd_run(rest: &[String]) -> ! {
    let split = rest.iter().position(|a| a == "--");
    let (opts, cmd): (&[String], Vec<String>) = match split {
        Some(i) => (&rest[..i], rest[i + 1..].to_vec()),
        None => {
            eprintln!("error: missing `--` before the command");
            exit(2);
        }
    };
    if cmd.is_empty() {
        eprintln!("error: no command after `--`");
        exit(2);
    }
    let (mut p, log, profile) = build_policy(opts, false); // run: quiet
    if p.writable_roots.is_empty() {
        eprintln!("warning: no --write roots; the command cannot write anywhere");
    }
    // Note: the environment is scrubbed to a safe allowlist by the BACKEND at spawn
    // (F-13, `Policy::child_env`), so secrets in the launcher's env never reach the
    // agent and the guarantee holds for any embedder, not just this CLI. The broker
    // and --private-tmp set their vars (proxy, TMPDIR) in this process's env below;
    // those names are in the allowlist, so they survive into the child.
    // Domain-scoped egress: start the capability broker and route the agent
    // through it (sets proxy env, grants the one loopback port). Mutates p.
    start_egress_broker(&mut p);
    // Print the profile's honest caveat before running — a tier must never
    // silently overclaim (esp. multi-tenant on a shared kernel).
    if let Some(pr) = profile {
        if let Some(c) = pr.caveat() {
            eprintln!("tartaros: profile {} — {}", pr.name(), c);
        }
    }
    let private_tmp = setup_private_tmp(&mut p);
    warn_reachable_host_sockets(&p);
    let code = run(&p, &cmd, log.as_deref());
    // Tear down the run-private temp dir (our own ephemeral scratch for this run).
    if let Some(dir) = private_tmp {
        let _ = std::fs::remove_dir_all(&dir);
    }
    exit(code);
}

/// `--private-tmp`: give the run its own temp dir, export it as TMPDIR, make it
/// writable, and (macOS) scope AF_UNIX bind/connect to it — so a headless
/// browser's control socket (Playwright publishes under `$TMPDIR`) lands in a
/// run-private dir instead of the shared temp where other runs' sockets live.
/// Returns the dir for teardown. No Playwright internals: we only set TMPDIR.
fn setup_private_tmp(p: &mut Policy) -> Option<std::path::PathBuf> {
    if !p.private_tmp {
        return None;
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("tartaros-tmp-{}-{}", std::process::id(), nanos));
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("tartaros: cannot create private tmp dir {}: {e}", dir.display());
        exit(1);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    // The child (and any tool that reads os.tmpdir()/TMPDIR) publishes here.
    for k in ["TMPDIR", "TMP", "TEMP"] {
        std::env::set_var(k, &dir);
    }
    p.writable_roots.push(dir.clone());
    p.unix_socket_subpaths.push(dir.clone());
    eprintln!(
        "tartaros: private tmp {} (exported as TMPDIR; AF_UNIX scoped to it on macOS)",
        dir.display()
    );
    Some(dir)
}

/// Never leave a host-escape silent (F-3). On Linux there is no per-path AF_UNIX
/// filtering — Landlock does not govern `connect()` to a pathname socket, and the
/// seccomp AF_UNIX deny is all-or-nothing — so a confined agent can still reach a
/// host daemon's unix socket (docker.sock, containerd, dbus, systemd), which is a
/// full host-escape vector. We cannot block it per-path, but we warn loudly when
/// the network is restricted, `--deny-unix` is off, and a dangerous socket is
/// present, and point to the fix. macOS denies AF_UNIX egress in the Seatbelt
/// profile natively, so this is Linux-only.
fn warn_reachable_host_sockets(p: &Policy) {
    use tartaros_core::Network;
    if cfg!(not(target_os = "linux")) {
        return;
    }
    if matches!(p.network, Some(Network::Allowed)) || p.deny_unix_sockets {
        return;
    }
    const DANGEROUS: &[&str] = &[
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/run/containerd/containerd.sock",
        "/run/podman/podman.sock",
        "/var/run/podman/podman.sock",
        "/run/dbus/system_bus_socket",
        "/run/systemd/private",
        "/var/run/libvirt/libvirt-sock",
    ];
    let found: Vec<&str> =
        DANGEROUS.iter().copied().filter(|s| std::path::Path::new(s).exists()).collect();
    if !found.is_empty() {
        eprintln!(
            "tartaros: warning: a host daemon socket is present and reachable by the \
             agent over AF_UNIX ({}) — Landlock cannot filter unix sockets by path, so \
             this is a host-escape vector. Add --deny-unix (or --profile hostile-code) \
             to block ALL AF_UNIX, or do not expose the socket.",
            found.join(", ")
        );
    }
}

/// If the policy names allowed egress domains, start the capability broker on
/// host loopback as a CONNECT/forward proxy scoped to those hosts (with SSRF
/// defense), point the agent's HTTP(S)_PROXY at it, and grant ONLY that loopback
/// port. The agent reaches the allowed domains through the broker and nothing
/// else — the broker is the one door out of the box.
fn start_egress_broker(p: &mut Policy) {
    if p.allow_domains.is_empty() {
        return;
    }
    // `--net` opens all egress, which would make the domain scope meaningless.
    if p.network == Some(Network::Allowed) {
        eprintln!("tartaros: --allow-domain scopes egress; it contradicts --net (allow all). Pick one.");
        exit(2);
    }
    // A fully isolated network namespace has only loopback *inside* it and cannot
    // reach the broker on the host's loopback, so the two are mutually exclusive.
    if p.isolate_network {
        eprintln!("tartaros: --allow-domain needs the host-loopback broker, which an isolated network namespace blocks. Drop one.");
        exit(2);
    }
    let hosts = p.allow_domains.clone();
    let broker = tartaros_broker::Broker::new(p.role.clone(), vec![])
        .insecure_no_auth() // loopback + the sandbox is the boundary; no secret to send
        .with_allowed_hosts(hosts.clone())
        .with_connect_ports(vec![443]) // HTTPS only: an allowed host is not a raw TCP endpoint (ADV-03)
        .with_allow_internal(false); // SSRF / rebinding defense stays on
    let (listener, port) = broker.bind(0).unwrap_or_else(|e| {
        eprintln!("tartaros: cannot start egress broker: {e}");
        exit(1);
    });
    // Grant exactly this one loopback port; all other egress remains denied.
    p.local_ports.push(port);
    // Route the agent through it. Set upper- and lower-case forms (tools differ),
    // and exempt loopback so the agent's own localhost traffic is not proxied.
    let proxy = format!("http://127.0.0.1:{port}");
    for k in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"] {
        std::env::set_var(k, &proxy);
    }
    for k in ["NO_PROXY", "no_proxy"] {
        std::env::set_var(k, "127.0.0.1,localhost,::1");
    }
    eprintln!("tartaros: egress broker on 127.0.0.1:{port} — allowed: {} (HTTPS/443; TCP tunnel, no TLS inspection)", hosts.join(", "));
    std::thread::spawn(move || {
        let mut sink = tartaros_core::VecSink::default();
        let _ = broker.serve(listener, &mut sink);
    });
}

fn cmd_explain(opts: &[String]) -> ! {
    let (p, _, profile) = build_policy(opts, true); // explain: verbose
    if let Some(pr) = profile {
        println!("profile: {} — {}", pr.name(), pr.tier());
        if let Some(c) = pr.caveat() {
            println!("profile caveat: {c}");
        }
        println!();
    }
    explain(&p);
    // Exit non-zero wherever `run` would refuse on THIS host, so an audit
    // (an external audit) never shows a green ✓ for a policy this host cannot enforce
    // (e.g. no Landlock on Docker Desktop's linuxkit kernel). Same fail-closed
    // contract as `run`, just without spawning anything.
    #[cfg(target_os = "linux")]
    let blocked = tartaros_linux::host_blocks_run(&p);
    #[cfg(target_os = "macos")]
    let blocked = tartaros_macos::host_blocks_run(&p);
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let blocked: Option<String> = None;
    if let Some(reason) = blocked {
        eprintln!("\ntartaros: this host cannot enforce this policy: {reason}");
        exit(2);
    }
    exit(0);
}

/// sandbox-runtime settings schema (the subset we read). An adapter maps it onto
/// the generic Policy; anything we cannot enforce makes the launch refuse.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct SandboxSettings {
    #[serde(default)]
    filesystem: SandboxFs,
    #[serde(default)]
    network: SandboxNet,
}
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct SandboxFs {
    #[serde(default, rename = "allowWrite")]
    allow_write: Vec<String>,
    #[serde(default, rename = "denyWrite")]
    deny_write: Vec<String>,
    #[serde(default, rename = "allowRead")]
    allow_read: Vec<String>,
    #[serde(default, rename = "denyRead")]
    deny_read: Vec<String>,
}
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct SandboxNet {
    #[serde(default, rename = "allowedDomains")]
    allowed_domains: Vec<String>,
    #[serde(default, rename = "deniedDomains")]
    denied_domains: Vec<String>,
    #[serde(default, rename = "allowUnixSockets")]
    allow_unix_sockets: Vec<String>,
    #[serde(default, rename = "allowLocalBinding")]
    allow_local_binding: bool,
    #[serde(default, rename = "allowMachLookup")]
    allow_mach_lookup: Vec<String>,
    #[serde(default, rename = "allowMachRegister")]
    allow_mach_register: Vec<String>,
}

/// Apply a sandbox-runtime settings file strictly: map the fields we can enforce
/// onto the generic policy, and REFUSE (exit) on any field we cannot guarantee,
/// rather than running under-enforced. "Apply fully or do not start."
/// How a settings path pattern resolves after unwrapping single-char classes.
enum PatKind {
    /// A concrete path (no remaining metacharacters).
    Literal,
    /// Any-depth pattern (contains `**`).
    AnyDepth,
    /// Single-segment glob (`*`/`?`/a real class, no `**`).
    SingleGlob,
}

/// Unwrap single-character classes `[x]` → `x`. sandbox-runtime callers
/// write `.vscod[e]` so a literal path is treated as a pattern (one class costs
/// fewer rules than a per-parent escape); such a pattern IS the literal path.
/// A multi-char class `[abc]` or a range is left intact (a real glob).
fn unwrap_char_classes(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len());
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '[' {
            let mut cls = String::new();
            let mut closed = false;
            while let Some(&n) = chars.peek() {
                chars.next();
                if n == ']' { closed = true; break; }
                cls.push(n);
            }
            if closed && cls.chars().count() == 1 {
                out.push_str(&cls); // single-char class == that literal char
            } else {
                out.push('['); out.push_str(&cls); if closed { out.push(']'); }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Classify a pattern (after unwrapping single-char classes). Returns the
/// normalized string and its kind.
fn classify(pattern: &str) -> (String, PatKind) {
    let s = unwrap_char_classes(pattern);
    let kind = if s.contains("**") {
        PatKind::AnyDepth
    } else if s.contains('*') || s.contains('?') || s.contains('[') {
        PatKind::SingleGlob
    } else {
        PatKind::Literal
    };
    (s, kind)
}

/// Is this any-depth pattern already covered by the built-in trust-handoff set
/// (which protects these surfaces at ANY depth under every writable root)? Match
/// on the config/git handoff names and on the config DIRECTORIES they live in, so
/// a `**/.claude` or `**/.codex` pattern is accepted — the dangerous surfaces
/// inside are already denied at any depth.
fn handoff_covers(pattern: &str) -> bool {
    use tartaros_core::{HANDOFF_CONFIG_NAMES, HANDOFF_GIT_NAMES};
    HANDOFF_CONFIG_NAMES
        .iter()
        .chain(HANDOFF_GIT_NAMES.iter())
        .any(|name| pattern.contains(name))
        || [".claude", ".codex", ".vscode", ".github", ".git"].iter().any(|d| pattern.contains(d))
}

fn apply_settings_file(p: &mut Policy, path: &str, verbose: bool) {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| { eprintln!("read {path}: {e}"); exit(2); });
    let s: SandboxSettings = serde_json::from_str(&text).unwrap_or_else(|e| { eprintln!("parse {path}: {e}"); exit(2); });
    let refuse = |what: &str| -> ! {
        eprintln!("tartaros: --settings: cannot guarantee {what} on this backend; refusing to run (apply-fully-or-refuse).");
        exit(2);
    };
    let refuse_glob = |x: &str| -> ! {
        eprintln!("tartaros: --settings: cannot enforce the glob pattern '{x}' on this backend — TartarOS has no general glob engine (Landlock matches by inode). Use a concrete path, the built-in trust-handoff set (.git/.claude/.codex/.mcp.json/…), or the macOS backend for single-* globs. Refusing (apply-fully-or-refuse).");
        exit(2);
    };
    // Filesystem. Each pattern is classified after unwrapping single-char classes
    // (a caller.s `.vscod[e]` is really a literal path). Literals map to the generic
    // carve; any-depth patterns must be covered by the trust-handoff set (else
    // refused — a `**` taken literally would protect nothing); single-* globs go to
    // the macOS regex backend, and are refused on Linux.
    // An ALLOW with any kind of glob is refused (we only re-allow concrete paths).
    for x in &s.filesystem.allow_write {
        match classify(x) { (n, PatKind::Literal) => p.writable_roots.push(PathBuf::from(expand(&n))), _ => refuse_glob(x) }
    }
    for x in &s.filesystem.allow_read {
        match classify(x) { (n, PatKind::Literal) => p.read_allows.push(PathBuf::from(expand(&n))), _ => refuse_glob(x) }
    }
    let map_deny = |x: &str, write: bool, read: bool, p: &mut Policy| {
        let (n, kind) = classify(x);
        match kind {
            PatKind::Literal => {
                let path = PathBuf::from(expand(&n));
                if write { p.fs_rules.push(FsRule { path: path.clone(), access: Access::Deny, even_if_absent: true }); }
                if read { p.read_denies.push(path); }
            }
            PatKind::AnyDepth => {
                if handoff_covers(&n) {
                    if verbose {
                        eprintln!("tartaros: --settings: '{x}' is covered by the built-in trust-handoff set at any depth; applying that.");
                    }
                } else {
                    refuse_glob(x);
                }
            }
            PatKind::SingleGlob => {
                // macOS compiles single-* globs to anchored regexes; Linux cannot.
                #[cfg(target_os = "macos")]
                { p.glob_denies.push(tartaros_core::GlobDeny { pattern: expand(&n), read, write }); }
                #[cfg(not(target_os = "macos"))]
                { let _ = (read, write); refuse_glob(x); }
            }
        }
    };
    for x in &s.filesystem.deny_read.clone() { map_deny(x, false, true, p); }
    for x in &s.filesystem.deny_write.clone() { map_deny(x, true, false, p); }
    // Network: we default-deny. Anything we cannot enforce in-sandbox is refused.
    p.network = Some(Network::Denied);
    // Per-domain egress IS enforceable: the broker runs as a CONNECT/forward proxy
    // scoped to these hosts and the agent gets no other egress. Map it through.
    p.allow_domains = s.network.allowed_domains.clone();
    if !s.network.denied_domains.is_empty() {
        refuse("per-domain deny lists");
    }
    // AF_UNIX: macOS Seatbelt allows specific socket paths; the Linux/seccomp
    // backend filters AF_UNIX all-or-nothing (cannot allow one socket by path).
    #[cfg(target_os = "macos")]
    {
        p.allow_unix_socket_paths =
            s.network.allow_unix_sockets.iter().map(|x| PathBuf::from(expand(x))).collect();
    }
    #[cfg(target_os = "linux")]
    {
        if s.network.allow_unix_sockets.is_empty() {
            p.deny_unix_sockets = true; // [] = no AF_UNIX at all
        } else {
            eprintln!("tartaros: --settings: cannot allow a specific AF_UNIX socket by path — the Linux/seccomp backend filters AF_UNIX all-or-nothing, not per path. Use an empty list to deny all, or run the macOS (Seatbelt) backend for per-path allow. Refusing (apply-fully-or-refuse).");
            exit(2);
        }
    }
    if s.network.allow_local_binding {
        refuse("blanket local binding (grant a concrete port with a port rule instead)");
    }
    // Mach rendezvous (headless browsers): sandbox-runtime writes a name with a
    // trailing `*` meaning a prefix; map it to a global-name-prefix. macOS-only —
    // Mach is a Darwin primitive, so a non-empty list refuses on Linux.
    #[cfg(target_os = "macos")]
    {
        let to_prefix = |x: &str| x.strip_suffix('*').unwrap_or(x).to_string();
        p.allow_mach_lookup = s.network.allow_mach_lookup.iter().map(|x| to_prefix(x)).collect();
        p.allow_mach_register = s.network.allow_mach_register.iter().map(|x| to_prefix(x)).collect();
    }
    #[cfg(target_os = "linux")]
    {
        if !s.network.allow_mach_lookup.is_empty() || !s.network.allow_mach_register.is_empty() {
            eprintln!("tartaros: --settings: allowMachLookup/allowMachRegister are macOS-only (Mach is a Darwin IPC primitive with no Linux equivalent). Run a headless-browser role under the macOS (Seatbelt) backend. Refusing (apply-fully-or-refuse).");
            exit(2);
        }
    }
    // Strict: a settings-driven run is guaranteed-or-abort.
    p.strict = true;
}

/// Parse a numeric flag value or exit with a clear message — never silently fall
/// back to 0, which would turn `--timeout 10m` into "no timeout" (a fail-open).
fn parse_num_or_exit<T: std::str::FromStr>(v: &str, flag: &str) -> T {
    v.parse().unwrap_or_else(|_| {
        eprintln!("error: {flag} expects a number, got '{v}'");
        exit(2);
    })
}

/// Build the Policy from --config (if any) + --profile + flags. Returns the
/// policy, the optional --log path, and the selected profile (for its caveat).
fn build_policy(opts: &[String], verbose: bool) -> (Policy, Option<String>, Option<Profile>) {
    let mut p = Policy { network: Some(Network::Denied), ..Default::default() };
    let mut profile: Option<Profile> = None;

    // First pass: load --config (a policy file), so flags can override it.
    if let Some(i) = opts.iter().position(|a| a == "--config") {
        let path = opts.get(i + 1).unwrap_or_else(|| { eprintln!("--config needs a path"); exit(2); });
        let text = std::fs::read_to_string(path).unwrap_or_else(|e| { eprintln!("read {path}: {e}"); exit(2); });
        let pf: PolicyFile = toml::from_str(&text).unwrap_or_else(|e| { eprintln!("parse {path}: {e}"); exit(2); });
        p.role = pf.role;
        p.writable_roots = pf.writable_roots.iter().map(|s| PathBuf::from(expand(s))).collect();
        p.read_denies = pf.read_denies.iter().map(|s| PathBuf::from(expand(s))).collect();
        p.read_allows = pf.read_allows.iter().map(|s| PathBuf::from(expand(s))).collect();
        p.fs_rules.extend(pf.write_denies.iter().map(|s| FsRule { path: PathBuf::from(expand(s)), access: Access::Deny, even_if_absent: true }));
        p.local_ports = pf.local_ports;
        p.network = Some(if pf.net { Network::Allowed } else { Network::Denied });
        p.deny_unix_sockets = pf.deny_unix_sockets;
        p.isolate_pids = pf.isolate_pids;
        p.isolate_network = pf.isolate_network;
        p.harden_syscalls = pf.harden_syscalls;
        p.strict = pf.strict;
        p.materialize_absent_handoff = pf.materialize_absent_handoff;
        p.isolate_process_info = pf.isolate_process_info;
        p.timeout = pf.timeout_secs.map(Duration::from_secs);
        p.max_memory_bytes = pf.max_memory_bytes;
        p.max_processes = pf.max_processes;
        p.max_cpu_secs = pf.max_cpu_secs;
        if let Some(name) = &pf.profile {
            profile = Some(Profile::parse(name).unwrap_or_else(|| {
                eprintln!("unknown profile in config: {name} (local-agent|hostile-code|multi-tenant)");
                exit(2);
            }));
        }
    }

    // --settings: apply a sandbox-runtime settings file through the generic
    // policy, strictly (guaranteed-or-refuse). It is just an adapter over the same
    // flags; the capabilities live in the sandbox, not in this shortcut.
    if let Some(i) = opts.iter().position(|a| a == "--settings") {
        let path = opts.get(i + 1).unwrap_or_else(|| { eprintln!("--settings needs a path"); exit(2); });
        apply_settings_file(&mut p, path, verbose);
    }

    // --profile on the command line overrides a config profile.
    if let Some(i) = opts.iter().position(|a| a == "--profile") {
        let name = opts.get(i + 1).unwrap_or_else(|| { eprintln!("--profile needs a name"); exit(2); });
        profile = Some(Profile::parse(name).unwrap_or_else(|| {
            eprintln!("unknown profile: {name} (local-agent|hostile-code|multi-tenant)");
            exit(2);
        }));
    }
    // Apply the profile baseline BEFORE flags, so explicit flags can still extend
    // it. Profiles only tighten; they never grant.
    if let Some(pr) = profile {
        pr.apply(&mut p);
    }

    let mut log: Option<String> = None;
    let mut it = opts.iter();
    while let Some(o) = it.next() {
        let mut val = || it.next().cloned().unwrap_or_else(|| { eprintln!("error: {o} needs a value"); exit(2); });
        match o.as_str() {
            "--config" => { let _ = val(); } // handled in the first pass
            "--settings" => { let _ = val(); } // handled above
            "--profile" => { let _ = val(); } // handled in the pre-scan above
            "--role" => p.role = val(),
            "--write" => p.writable_roots.push(PathBuf::from(expand(&val()))),
            "--read-deny" => p.read_denies.push(PathBuf::from(expand(&val()))),
            "--read-allow" => p.read_allows.push(PathBuf::from(expand(&val()))),
            "--write-deny" => p.fs_rules.push(FsRule { path: PathBuf::from(expand(&val())), access: Access::Deny, even_if_absent: true }),
            "--port" => p.local_ports.push(val().parse().unwrap_or_else(|_| { eprintln!("bad --port"); exit(2); })),
            "--allow-domain" => p.allow_domains.push(val()),
            "--net" => p.network = Some(Network::Allowed),
            "--deny-unix" => p.deny_unix_sockets = true,
            "--isolate-pids" => p.isolate_pids = true,
            "--isolate-net" => p.isolate_network = true,
            "--seccomp-strict" => p.harden_syscalls = true,
            "--strict" => p.strict = true,
            "--materialize" => p.materialize_absent_handoff = true,
            "--private-tmp" => p.private_tmp = true,
            "--browser" => p.browser = true,
            "--inherit-env" => p.inherit_env = true,
            "--env" => p.env_passthrough.push(val()),
            "--timeout" => p.timeout = Some(Duration::from_secs(parse_num_or_exit(&val(), "--timeout (seconds)"))),
            "--max-mem" => p.max_memory_bytes = Some(parse_num_or_exit(&val(), "--max-mem (bytes)")),
            "--max-procs" => p.max_processes = Some(parse_num_or_exit(&val(), "--max-procs")),
            "--max-cpu" => p.max_cpu_secs = Some(parse_num_or_exit(&val(), "--max-cpu (seconds)")),
            "--isolate-proc" => p.isolate_process_info = true,
            "--log" => log = Some(val()),
            other => { eprintln!("unknown option: {other}"); exit(2); }
        }
    }
    (p, log, profile)
}

/// Print exactly what a policy grants, without running anything — so a security
/// team can audit a profile before deploying it.
fn explain(p: &Policy) {
    println!("role: {}", if p.role.is_empty() { "(unset)" } else { &p.role });
    println!("network: {:?}", p.network);
    if !p.local_ports.is_empty() {
        println!("loopback ports: {:?}", p.local_ports);
    }
    if !p.allow_domains.is_empty() {
        println!("egress domains (via broker, HTTPS/CONNECT + SSRF defense): {}", p.allow_domains.join(", "));
    }
    println!("deny AF_UNIX sockets: {}", p.deny_unix_sockets);
    if !p.allow_mach_register.is_empty() {
        println!("macOS Mach register (prefix): {}", p.allow_mach_register.join(", "));
    }
    if !p.allow_mach_lookup.is_empty() {
        println!("macOS Mach lookup (prefix): {}", p.allow_mach_lookup.join(", "));
    }
    if p.private_tmp {
        println!("private tmp: a run-private TMPDIR is created, made writable, and AF_UNIX-scoped (macOS)");
    }
    for d in &p.unix_socket_subpaths {
        println!("AF_UNIX bind/connect scoped to (subpath): {}", d.display());
    }
    println!("isolate PID namespace: {}", p.isolate_pids);
    println!("isolate network (no egress): {}", p.isolate_network);
    println!("seccomp attack-surface reduction: {}", p.harden_syscalls);
    println!("strict (guaranteed-or-abort): {}", p.strict);
    println!("isolate /proc (env reads): {}", p.isolate_process_info);
    if p.inherit_env {
        println!("environment: FULL passthrough (--inherit-env) — launcher env, incl. any secrets, is inherited");
    } else {
        println!("environment: scrubbed to safe allowlist ({})", tartaros_core::ENV_ALLOWLIST.join(", "));
        println!("  + LC_* (locale)");
        if !p.env_passthrough.is_empty() {
            println!("  + explicit --env: {}", p.env_passthrough.join(", "));
        }
    }
    if let Some(t) = p.timeout { println!("timeout: {}s", t.as_secs()); }
    if let Some(m) = p.max_memory_bytes { println!("max memory: {m} bytes"); }
    if let Some(n) = p.max_processes { println!("max processes: {n}"); }
    if let Some(c) = p.max_cpu_secs { println!("max cpu: {c}s (RLIMIT_CPU)"); }
    println!("\nwritable roots:");
    for r in &p.writable_roots { println!("  + {}", r.display()); }
    println!("\nwrite-denied (inside writable roots):");
    for r in p.fs_rules.iter().filter(|r| r.access == Access::Deny) {
        println!("  x {}", r.path.display());
    }
    println!("\nread-denied (secrets):");
    for r in &p.read_denies { println!("  - {}", r.display()); }
    if !p.read_allows.is_empty() {
        println!("\nread re-allowed (inside a read-deny):");
        for r in &p.read_allows { println!("  + {}", r.display()); }
    }
    // The handoff set is protected by NAME at any depth under each writable root.
    // We list the names themselves, not an enumeration of matching paths on disk:
    // the protection covers paths that do not exist yet (pre-planting defense), and
    // walking a large writable tree (e.g. --write /tmp) just to print it would be a
    // needless stat storm.
    println!("\ntrust-handoff protected (deny write at any depth under each writable root):");
    for name in tartaros_core::HANDOFF_CONFIG_NAMES { println!("  ! **/{name}"); }
    for name in tartaros_core::HANDOFF_GIT_NAMES { println!("  ! **/{name}  (in any git repo)"); }

    // What this policy ACTUALLY enforces on THIS host (probed), so guarantees can
    // be verified up front rather than discovered from stderr warnings at runtime.
    println!("\nenforcement on this host:");
    #[cfg(target_os = "macos")]
    for line in tartaros_macos::enforcement_report(p) { println!("  · {line}"); }
    #[cfg(target_os = "linux")]
    for line in tartaros_linux::enforcement_report(p) { println!("  · {line}"); }

    #[cfg(target_os = "macos")]
    {
        println!("\n--- macOS Seatbelt profile ---");
        println!("{}", tartaros_macos::compile_profile(p));
    }
    #[cfg(target_os = "linux")]
    {
        let bind = tartaros_linux::uses_bind_mounts(p);
        if bind {
            println!("\n--- Linux enforcement: whole workspace writable + read-only bind mounts ---");
            println!("The EXISTING trust-handoff set is protected by read-only bind mounts (mount");
            println!("namespace), so new entries CAN be created at a writable root while existing");
            println!("handoff paths stay unwritable.");
            println!("warning: because the whole root is writable, a NOT-YET-EXISTING handoff path");
            println!("(e.g. a new top-level .claude/settings.json, or a newly-created nested git");
            println!("repo's .git/hooks) is NOT protected under this strategy — only paths that");
            println!("exist when the sandbox starts are bound read-only. Pre-planting defense for");
            println!("absent paths is a macOS (Seatbelt regex) property; on Linux it needs the carve");
            println!("+ --materialize (top-level only), which is mutually exclusive with whole-root");
            println!("create-at-root. The real-world attack (poisoning an EXISTING repo config) is");
            println!("blocked; seeding a brand-new config/repo for a later trusted tool is not.");
        } else {
            println!("\n--- Linux Landlock allow-lists (based on the current filesystem) ---");
            println!("write (carved):");
            for a in p.linux_write_allowlist() { println!("  w {}", a.display()); }
            println!("read (carved):");
            for a in p.linux_read_allowlist() { println!("  r {}", a.display()); }
            println!("note: writes grant write-only; reads are governed by the read carve.");
            // Warn where the carve cannot allow creating NEW entries directly at a
            // writable root (a trust-handoff/explicit deny sits below). This is LESS
            // permission, not a contract break — a consumer surfaces it as a notice.
            // Running with mount privileges (root/container) lifts it via bind mounts.
            for root in &p.writable_roots {
                let deny_below = p.trust_handoff_rules().iter().any(|r| r.path.starts_with(root) && r.path.exists())
                    || p.fs_rules.iter().any(|r| r.access == Access::Deny && r.path.starts_with(root) && r.path.exists());
                if deny_below {
                    println!(
                        "warning: on Linux, new entries cannot be created directly in {} (Landlock cannot subtract .git/hooks); existing files and subdirectories are writable. Run with mount privileges (root/container) to lift this via read-only bind mounts.",
                        root.display()
                    );
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn run(policy: &Policy, cmd: &[String], log: Option<&str>) -> i32 {
    run_common(&tartaros_linux::LandlockBackend, policy, cmd, log, true)
}

#[cfg(target_os = "macos")]
fn run(policy: &Policy, cmd: &[String], log: Option<&str>) -> i32 {
    run_common(&tartaros_macos::SeatbeltBackend, policy, cmd, log, true)
}

/// Shared run path (both OS): `--log` goes through `run_observed`, which uses the
/// SAME supervisor (timeout, limits, reaping) as `run` — enabling the log never
/// changes the enforcement guarantees (review P0). `net` selects whether to add
/// the network collector.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_common<B>(be: &B, policy: &Policy, cmd: &[String], log: Option<&str>, net: bool) -> i32
where
    B: RunObserved,
{
    use tartaros_collect::{FileCollector, NetworkCollector, ProcessCollector, SecretCollector};
    use tartaros_core::{Collector, FilterSink, JsonlSink, RecordMode};
    match log {
        Some(path) => {
            let f = match std::fs::OpenOptions::new().create(true).append(true).open(path) {
                Ok(f) => f,
                Err(e) => { eprintln!("tartaros: cannot open log {path}: {e}"); return 1; }
            };
            let mut sink = FilterSink::new(JsonlSink::new(f), RecordMode::Boundary);
            let pol = policy.clone();
            let res = be.run_observed(policy, cmd, &mut sink, move |pid| {
                let mut v: Vec<Box<dyn Collector>> = Vec::new();
                if net { v.push(Box::new(NetworkCollector::for_policy(pid, &pol))); }
                v.push(Box::new(SecretCollector::for_policy(pid, &pol)));
                v.push(Box::new(ProcessCollector::for_policy(pid, &pol)));
                v.push(Box::new(FileCollector::for_policy(pid, &pol)));
                v
            });
            match res { Ok(o) => o.exit_code, Err(e) => { eprintln!("tartaros: {}", e.reason); 1 } }
        }
        None => match be.run(policy, cmd) {
            Ok(o) => o.exit_code,
            Err(e) => { eprintln!("tartaros: {}", e.reason); 1 }
        },
    }
}

/// Minimal trait so `run_common` can call either backend's `run_observed`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
trait RunObserved: tartaros_core::Backend {
    fn run_observed<F>(
        &self,
        policy: &Policy,
        command: &[String],
        sink: &mut dyn tartaros_core::EffectSink,
        make: F,
    ) -> Result<tartaros_core::RunOutcome, tartaros_core::RunError>
    where
        F: FnOnce(u32) -> Vec<Box<dyn tartaros_core::Collector>>;
}

#[cfg(target_os = "linux")]
impl RunObserved for tartaros_linux::LandlockBackend {
    fn run_observed<F>(&self, policy: &Policy, command: &[String], sink: &mut dyn tartaros_core::EffectSink, make: F)
        -> Result<tartaros_core::RunOutcome, tartaros_core::RunError>
    where F: FnOnce(u32) -> Vec<Box<dyn tartaros_core::Collector>> {
        tartaros_linux::LandlockBackend::run_observed(self, policy, command, sink, make)
    }
}

#[cfg(target_os = "macos")]
impl RunObserved for tartaros_macos::SeatbeltBackend {
    fn run_observed<F>(&self, policy: &Policy, command: &[String], sink: &mut dyn tartaros_core::EffectSink, make: F)
        -> Result<tartaros_core::RunOutcome, tartaros_core::RunError>
    where F: FnOnce(u32) -> Vec<Box<dyn tartaros_core::Collector>> {
        tartaros_macos::SeatbeltBackend::run_observed(self, policy, command, sink, make)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn run(_policy: &Policy, _cmd: &[String], _log: Option<&str>) -> i32 {
    eprintln!("tartaros: unsupported OS");
    1
}
