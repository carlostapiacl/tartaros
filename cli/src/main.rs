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
//!   --allow-home-handoff   allow writing shell rc / .gitconfig / .ripgreprc (denied by default)
//!   --private-tmp          run-private TMPDIR, AF_UNIX scoped to it (headless browsers)
//!   --mach-lookup-only     macOS: allowMachLookup opens ONLY its prefixes (no curated base)
//!   --env KEY[=VALUE]      carry one launcher var through, or set it (default: env is scrubbed)
//!   --inherit-env          inherit the full launcher env (opt into leaking secrets)
//!   --timeout SECS         kill the process group after SECS (exit 124)
//!   --max-mem BYTES        address-space limit
//!   --max-procs N          process limit
//!   --max-cpu SECS         total CPU-seconds limit (RLIMIT_CPU; root-proof)
//!   --log FILE             write the effect log here, the egress broker's decisions included
//!   --log-format F         jsonl (default) or otlp (OpenTelemetry, with the launcher's TRACEPARENT)
//!   --settings FILE        map a sandbox-runtime settings.json onto the generic
//!                          policy; refuses (exit 78) on anything it can't guarantee
//!
//! Exit code is the command's (128+signal on signal death, 124 on timeout); TartarOS's
//! own are 78 (policy refused, nothing ran), 2 (bad command line), 1 (could not run).

use tartaros_core::{Access, FsRule, Network, Policy, Profile};
use serde::Deserialize;

#[cfg(target_os = "linux")]
mod egress_ns;

/// Teardown guard for scoped-egress state held across the run. On Linux it owns the
/// network namespace (NET-01); elsewhere there is nothing to tear down.
#[cfg(target_os = "linux")]
type EgressGuard = Option<egress_ns::EgressNs>;
#[cfg(not(target_os = "linux"))]
type EgressGuard = ();
use std::path::PathBuf;
use std::process::exit;
use std::time::Duration;

/// Exit code when TartarOS refuses the POLICY — a field or combination this backend
/// cannot enforce, so nothing ran. Distinct from 1 (TartarOS could not start or run:
/// broker, log, temp dir, a host missing a requested guarantee) and 2 (bad command
/// line). 78 is sysexits' EX_CONFIG.
const EXIT_POLICY_REFUSED: i32 = 78;

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
    /// Unset keeps the default (protected); `false` is the dotfiles-repo opt-out.
    #[serde(default)]
    protect_home_handoff: Option<bool>,
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
    /// The credential broker: capabilities the agent uses without holding their
    /// secret. Only in a policy file (it needs nested tables).
    #[serde(default)]
    broker: Option<BrokerFile>,
}

/// `[broker]`: a loopback HTTP broker for this run. The agent sends a per-run
/// token; the broker serves `[[broker.capability]]` endpoints, injecting secrets
/// it reads from the launcher's environment (never from the file, never into the
/// agent's). With `allowed_hosts` it also forwards plain HTTP and CONNECT to those
/// hosts; without, it forwards nothing.
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct BrokerFile {
    /// Loopback port to listen on (0 or unset: any free port). Granted to the agent.
    #[serde(default)]
    port: u16,
    /// Launcher env var holding the token the agent must send. Unset: a random
    /// per-run token. Either way the agent gets it as TARTAROS_BROKER_TOKEN.
    #[serde(default)]
    token_env: Option<String>,
    /// Header that carries the token (default X-Tartaros-Auth).
    #[serde(default)]
    auth_header: Option<String>,
    #[serde(default)]
    allowed_hosts: Vec<String>,
    /// Let an allowed host that resolves to an internal address be reached
    /// (off: the SSRF defense).
    #[serde(default)]
    allow_internal: bool,
    #[serde(default)]
    capability: Vec<CapabilityFile>,
    /// Headers injected into plain-HTTP requests forwarded to an allowed host
    /// (HTTPS through CONNECT is a blind tunnel: use a capability for it).
    #[serde(default)]
    inject: Vec<HostInjectFile>,
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct HostInjectFile {
    host: String,
    header: String,
    value_env: String,
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct CapabilityFile {
    /// `/prefix`: the agent asks the broker for `/prefix/rest`.
    prefix: String,
    /// The real endpoint: `/prefix/rest` becomes `upstream/rest`.
    upstream: String,
    /// Methods allowed (default GET only).
    #[serde(default)]
    methods: Vec<String>,
    #[serde(default)]
    inject: Vec<InjectFile>,
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct InjectFile {
    header: String,
    /// Launcher env var holding the header's value (the secret).
    value_env: String,
}

/// The `[broker]` of the policy file, if any (set while the policy is built).
static BROKER: std::sync::OnceLock<BrokerFile> = std::sync::OnceLock::new();

/// Expand a leading `~` to $HOME so policy files are portable.
fn expand(s: &str) -> String {
    if let Some(rest) = s.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}/{rest}");
        }
    }
    s.to_string()
}

/// Like [`expand`], but also resolve a relative path to absolute against the
/// current working directory. The backends require absolute writable/deny roots
/// (the sandbox profile must be unambiguous), and cwd is well-defined at launch —
/// so a user's `./repo` is resolved here rather than rejected with "must be
/// absolute". Used only for concrete path flags, never for glob patterns (which
/// stay relative by design, e.g. `**/*.pem`).
fn expand_path(s: &str) -> String {
    let s = expand(s);
    let p = std::path::Path::new(&s);
    if p.is_absolute() {
        return s;
    }
    match std::env::current_dir() {
        Ok(cwd) => cwd.join(p).to_string_lossy().into_owned(),
        Err(_) => s,
    }
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
    } else if cfg!(target_os = "windows") {
        #[cfg(target_os = "windows")]
        {
            match tartaros_windows::Tier::from_env() {
                tartaros_windows::Tier::AppContainer => "windows/appcontainer",
                tartaros_windows::Tier::SandboxUser => "windows/sandbox-user",
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            "windows"
        }
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
  --config FILE          load a TOML policy (flags override it); its [broker]
                         table starts the credential broker (docs/broker.md)
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
  --allow-home-handoff   let the agent write shell rc / .gitconfig / .ripgreprc in its
                         roots (denied by default; for dotfiles repos)
  --private-tmp          run-private TMPDIR; AF_UNIX scoped to it (headless browsers)
  --browser              macOS: minimal extra Seatbelt grants for headless Chromium/Chrome
  --mach-lookup-only     macOS: allowMachLookup opens ONLY its prefixes, without the
                         curated base of system services (breaks the keychain, etc.)

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
  --log FILE             write the first-hand effect log (JSON Lines), the egress
                         broker's connect decisions included
  --log-format F         jsonl (default) or otlp: OpenTelemetry log records in the
                         open effect schema, with the launcher's TRACEPARENT

Exit code is the command's (128+signal on signal death, 124 on timeout). TartarOS's own:
  78  the policy was refused (this backend cannot enforce it); nothing ran
  2   bad command line
  1   TartarOS could not start or run the command
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
    // through it. On Linux-as-root this builds a scoped network namespace (NET-01);
    // the returned guard tears it (netns + veth + firewall rule) down after the run.
    let egress_guard = start_egress_broker(&mut p, log.as_ref());
    start_credential_broker(&mut p);
    // Print the profile's honest caveat before running — a tier must never
    // silently overclaim (esp. multi-tenant on a shared kernel).
    if let Some(pr) = profile {
        if let Some(c) = pr.caveat() {
            eprintln!("tartaros: profile {} — {}", pr.name(), c);
        }
    }
    let private_tmp = setup_private_tmp(&mut p);
    warn_reachable_host_sockets(&p);
    let code = run(&p, &cmd, log.as_ref());
    // Tear down the run-private temp dir (our own ephemeral scratch for this run).
    if let Some(dir) = private_tmp {
        let _ = std::fs::remove_dir_all(&dir);
    }
    // Drop the egress guard here: `process::exit` below skips destructors, so the
    // scoped network namespace (+ veth + firewall rule) would otherwise leak. The
    // `let _ =` binding drops it immediately (a no-op on non-Linux, where it is ()).
    #[cfg(target_os = "linux")]
    std::mem::drop(egress_guard);
    #[cfg(not(target_os = "linux"))]
    let _ = egress_guard;
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
    let dir = match create_private_tmp() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("tartaros: cannot create private tmp dir: {e}");
            exit(1);
        }
    };
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

/// Create the run-private temp dir with a SHORT path. AF_UNIX socket paths are
/// capped at 104 bytes (macOS) / 108 (Linux), and tools nest their sockets a few
/// levels under `$TMPDIR` (Playwright's socket dir landed at 107 bytes under a
/// `/var/folders/…` TMPDIR). So: a short per-user base, `/private/tmp/tartaros-<uid>`
/// (`/tmp/…` on Linux), 0700 and verified to be ours, holding `tt-<6 random>`.
#[cfg(unix)]
fn create_private_tmp() -> std::io::Result<std::path::PathBuf> {
    use std::io::{Error, ErrorKind, Read};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    let uid = unsafe { libc::getuid() };
    let root = if cfg!(target_os = "macos") { "/private/tmp" } else { "/tmp" };
    let base = std::path::PathBuf::from(format!("{root}/tartaros-{uid}"));
    match std::fs::DirBuilder::new().mode(0o700).create(&base) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
        Err(e) => return Err(Error::new(e.kind(), format!("{}: {e}", base.display()))),
    }
    // /tmp is world-writable: the base may have been planted by someone else, or be
    // a symlink. lstat (never follow) and require a real dir we own, then 0700.
    let md = std::fs::symlink_metadata(&base)?;
    if !md.file_type().is_dir() || md.uid() != uid {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            format!("{} is not a directory owned by uid {uid}; refusing to use it", base.display()),
        ));
    }
    if md.mode() & 0o077 != 0 {
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700))?;
    }
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut urandom = std::fs::File::open("/dev/urandom")?;
    for _ in 0..16 {
        let mut b = [0u8; 6];
        urandom.read_exact(&mut b)?;
        let suffix: String = b.iter().map(|x| ALPHABET[*x as usize % ALPHABET.len()] as char).collect();
        let dir = base.join(format!("tt-{suffix}"));
        match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(Error::new(e.kind(), format!("{}: {e}", dir.display()))),
        }
    }
    Err(Error::new(ErrorKind::AlreadyExists, format!("no free name under {}", base.display())))
}

#[cfg(not(unix))]
fn create_private_tmp() -> std::io::Result<std::path::PathBuf> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("tt-{}-{}", std::process::id(), nanos));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
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
/// host side as a CONNECT/forward proxy scoped to those hosts (with SSRF defense)
/// and point the agent's HTTP(S)_PROXY at it. NET-01: a Landlock port grant alone
/// cannot stop the agent reaching an external host on the broker's port, so on
/// Linux-as-root we instead run the agent in a network namespace whose only route
/// is a veth to the broker (no default route) — the broker becomes the one door out
/// at the network layer, fail-closed. macOS filters egress by address (no gap). The
/// non-root fallback is the bare port grant with a loud NET-01 warning.
fn start_egress_broker(p: &mut Policy, log: Option<&LogSpec>) -> EgressGuard {
    if p.allow_domains.is_empty() {
        return Default::default();
    }
    // `--net` opens all egress, which would make the domain scope meaningless.
    if p.network == Some(Network::Allowed) {
        eprintln!("tartaros: --allow-domain scopes egress; it contradicts --net (allow all). Pick one.");
        exit(2);
    }
    if p.isolate_network {
        eprintln!("tartaros: --allow-domain runs the broker and bridges it into the agent's network namespace; it contradicts --isolate-net (no egress at all). Drop one.");
        exit(2);
    }
    let hosts = p.allow_domains.clone();
    // The broker's decisions go to the run's --log (its own append handle, the same
    // filter as the supervisor's), or nowhere: before, they went to an in-memory sink
    // nobody read, so a run's egress decisions were lost.
    let open_sink = {
        let log = log.cloned();
        move || -> Box<dyn tartaros_core::EffectSink> {
            match log.as_ref().map(|l| (l, l.open())) {
                Some((_, Ok(s))) => Box::new(tartaros_core::FilterSink::new(s, tartaros_core::RecordMode::Boundary)),
                Some((l, Err(e))) => {
                    eprintln!("tartaros: cannot open log {} for the egress broker: {e}", l.path);
                    Box::new(tartaros_core::DiscardSink)
                }
                None => Box::new(tartaros_core::DiscardSink),
            }
        }
    };
    // The role's declared loopback ports (--port): the agent may reach these local
    // services (MCP core, model proxy) THROUGH the broker too, for clients that
    // route everything via HTTP_PROXY. Captured before the broker's own port is
    // appended to local_ports below, so the broker never forwards to itself.
    let loopback_ports = p.local_ports.clone();
    let make_broker = || {
        tartaros_broker::Broker::new(p.role.clone(), vec![])
            .insecure_no_auth() // the sandbox boundary is the auth; no secret to send
            .with_allowed_hosts(hosts.clone())
            .with_connect_ports(vec![443]) // HTTPS only (ADV-03)
            .with_allow_internal(false) // SSRF / rebinding defense stays on
            .with_loopback_ports(loopback_ports.clone()) // declared local_ports (N1)
    };
    // `exempt_loopback`: whether to put loopback in NO_PROXY so the agent connects
    // to a declared local_port DIRECTLY. True in the loopback-broker posture (macOS,
    // non-root Linux): the broker and the local services share the agent's loopback,
    // so a direct connection is correct. FALSE in the NET-01 netns posture: there the
    // agent's loopback is its OWN (empty) netns loopback, NOT the host's where the
    // local services live — so loopback must route THROUGH the broker, which forwards
    // to the host loopback. Either way declared local_ports stay reachable.
    let set_proxy = |ip: &str, port: u16, exempt_loopback: bool| {
        let proxy = format!("http://{ip}:{port}");
        for k in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"] {
            std::env::set_var(k, &proxy);
        }
        let no_proxy = if exempt_loopback { "127.0.0.1,localhost,::1" } else { "" };
        for k in ["NO_PROXY", "no_proxy"] {
            std::env::set_var(k, no_proxy);
        }
    };

    // NET-01 closure (Linux, root): run the agent in a network namespace whose only
    // route is a veth to the broker's host IP — no default route — so it reaches the
    // broker and nothing else. Fail-closed: if the namespace cannot be built AND
    // verified isolating, tear down and fall back to the loopback broker with the
    // documented NET-01 warning (a known, honest non-guarantee), never a silent
    // weaker mode.
    #[cfg(target_os = "linux")]
    if !p.isolate_network && egress_ns::available() {
        let broker = make_broker();
        let hosts_for_log = hosts.clone();
        let open_ns_sink = open_sink.clone();
        let bind_on = move |ip: &str| -> std::io::Result<u16> {
            let (listener, port) = broker.bind_addr(ip, 0)?;
            std::thread::spawn(move || {
                let mut sink = Tee(tartaros_broker::RefusalReport::stderr(), open_ns_sink());
                let _ = broker.serve(listener, &mut sink);
            });
            let _ = &hosts_for_log;
            Ok(port)
        };
        match egress_ns::setup(bind_on) {
            Ok((ns, port)) => {
                p.local_ports.push(port); // reach the broker inside the netns
                p.egress_netns = Some(ns.name.clone());
                set_proxy(&ns.host_ip, port, false); // netns: loopback via broker
                eprintln!(
                    "tartaros: egress broker on {}:{port} in a scoped network namespace — allowed: {} (NET-01 closed: the agent has no route except to the broker)",
                    ns.host_ip,
                    hosts.join(", ")
                );
                return Some(ns);
            }
            Err(reason) => {
                eprintln!("tartaros: warning: could not build the scoped egress namespace ({reason}); falling back to the loopback broker. {}", NET01_FALLBACK);
            }
        }
    }

    // Windows: the agent runs as a separate user whose egress is blocked by a
    // per-SID WFP filter that permits exactly ONE loopback port (installed with
    // admin at setup). The broker must bind that fixed port, not a random one; a
    // run-time process cannot add a WFP permit (no admin). The port is not added
    // to local_ports — the WFP permit, not a port grant, is what lets the agent
    // reach it. Fail closed if the setup did not configure a broker channel.
    #[cfg(target_os = "windows")]
    {
        let Some(port) = tartaros_windows::configured_broker_port() else {
            eprintln!("tartaros: --allow-domain needs a broker channel; run setup/sandbox-user.ps1 install -BrokerPort <port> once (elevated).");
            exit(2);
        };
        let broker = make_broker();
        let listener = broker.bind_addr("127.0.0.1", port).map(|(l, _)| l).unwrap_or_else(|e| {
            eprintln!("tartaros: cannot start egress broker on 127.0.0.1:{port}: {e}");
            exit(1);
        });
        set_proxy("127.0.0.1", port, false); // route everything (incl. loopback) via the broker
        eprintln!("tartaros: egress broker on 127.0.0.1:{port} — allowed: {} (HTTPS/443; TCP tunnel, no TLS inspection)", hosts.join(", "));
        std::thread::spawn(move || {
            let mut sink = tartaros_broker::RefusalReport::stderr();
            let _ = broker.serve(listener, &mut sink);
        });
        return Default::default();
    }

    // Fallback (macOS, non-root Linux, or netns setup failed): loopback broker.
    #[cfg(not(target_os = "windows"))]
    {
    let broker = make_broker();
    let (listener, port) = broker.bind(0).unwrap_or_else(|e| {
        eprintln!("tartaros: cannot start egress broker: {e}");
        exit(1);
    });
    p.local_ports.push(port);
    set_proxy("127.0.0.1", port, true); // loopback broker: direct loopback ok
    eprintln!("tartaros: egress broker on 127.0.0.1:{port} — allowed: {} (HTTPS/443; TCP tunnel, no TLS inspection)", hosts.join(", "));
    #[cfg(target_os = "linux")]
    eprintln!("tartaros: warning: {NET01_FALLBACK}");
    std::thread::spawn(move || {
        let mut sink = Tee(tartaros_broker::RefusalReport::stderr(), open_sink());
        let _ = broker.serve(listener, &mut sink);
    });
    Default::default()
    }
}

/// Start the policy file's `[broker]`, if any, on loopback, and give the agent
/// its address and token (TARTAROS_BROKER_URL, TARTAROS_BROKER_TOKEN). A secret
/// named by `value_env` that is not set aborts the run: a capability that would
/// inject an empty credential is a misconfiguration, not a degraded mode.
fn start_credential_broker(p: &mut Policy) {
    let Some(cfg) = BROKER.get().cloned() else { return };
    let env = |name: &str, what: &str| -> String {
        std::env::var(name).unwrap_or_else(|_| {
            eprintln!("tartaros: [broker] {what} names ${name}, which is not set in the launcher's environment");
            exit(78);
        })
    };
    let token = match &cfg.token_env {
        Some(name) => env(name, "token_env"),
        None => random_token().unwrap_or_else(|e| {
            eprintln!("tartaros: [broker] cannot make a random token ({e}); set token_env");
            exit(1);
        }),
    };
    let mut caps = Vec::new();
    for c in &cfg.capability {
        if !c.prefix.starts_with('/') || c.prefix.len() < 2 || c.prefix.ends_with('/') {
            eprintln!("tartaros: [broker] capability prefix {:?} must look like /name", c.prefix);
            exit(2);
        }
        let methods = if c.methods.is_empty() { vec!["GET".into()] } else { c.methods.iter().map(|m| m.to_uppercase()).collect() };
        let injections = c
            .inject
            .iter()
            .map(|i| tartaros_broker::Injection { host: None, header: i.header.clone(), value: env(&i.value_env, "inject.value_env") })
            .collect();
        caps.push(tartaros_broker::Capability { prefix: c.prefix.clone(), upstream_base: c.upstream.clone(), methods, injections });
    }
    let host_injections = cfg
        .inject
        .iter()
        .map(|i| tartaros_broker::Injection { host: Some(i.host.clone()), header: i.header.clone(), value: env(&i.value_env, "inject.value_env") })
        .collect();
    let mut broker = tartaros_broker::Broker::new(p.role.clone(), host_injections)
        .with_auth(token.clone())
        .with_capabilities(caps)
        .with_allowed_hosts(cfg.allowed_hosts.clone())
        .with_allow_internal(cfg.allow_internal);
    if let Some(h) = &cfg.auth_header {
        broker = broker.with_auth_header(h.clone());
    }
    if cfg.allowed_hosts.is_empty() {
        broker = broker.without_forwarding();
    }
    let (listener, port) = broker.bind(cfg.port).unwrap_or_else(|e| {
        eprintln!("tartaros: cannot start the credential broker on 127.0.0.1:{}: {e}", cfg.port);
        exit(1);
    });
    if !p.local_ports.contains(&port) {
        p.local_ports.push(port);
    }
    p.env_passthrough.push(format!("TARTAROS_BROKER_URL=http://127.0.0.1:{port}"));
    p.env_passthrough.push(format!("TARTAROS_BROKER_TOKEN={token}"));
    eprintln!(
        "tartaros: credential broker on 127.0.0.1:{port} — {} capabilit{}{}",
        cfg.capability.len(),
        if cfg.capability.len() == 1 { "y" } else { "ies" },
        if cfg.allowed_hosts.is_empty() { String::new() } else { format!(", forwards to {}", cfg.allowed_hosts.join(", ")) }
    );
    std::thread::spawn(move || {
        let mut sink = tartaros_broker::RefusalReport::stderr();
        let _ = broker.serve(listener, &mut sink);
    });
}

/// 32 hex characters from the OS's random source.
fn random_token() -> std::io::Result<String> {
    #[cfg(unix)]
    {
        use std::io::Read;
        let mut b = [0u8; 16];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut b)?;
        Ok(b.iter().map(|x| format!("{x:02x}")).collect())
    }
    #[cfg(not(unix))]
    Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "no /dev/urandom here"))
}

#[cfg(target_os = "linux")]
const NET01_FALLBACK: &str = "egress scoping now relies on a port grant that Landlock cannot pin to loopback (NET-01) — a malicious agent that learns the port could reach an external host on it, bypassing the broker. Safe for a trusted-but-fallible agent; for hostile code run as root so the scoped network namespace can be used.";

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
    #[cfg(target_os = "windows")]
    let blocked = {
        use tartaros_core::Backend;
        tartaros_windows::WindowsBackend.validate(&p).err().map(|e| e.reason)
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    let blocked: Option<String> = None;
    if let Some(reason) = blocked {
        eprintln!("\ntartaros: this host cannot enforce this policy: {reason}");
        exit(EXIT_POLICY_REFUSED);
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
// Some fields drive the macOS/Linux settings path only; on Windows that code is
// cfg'd out, so they read as dead there without being removed from the schema.
#[cfg_attr(target_os = "windows", allow(dead_code))]
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
        exit(EXIT_POLICY_REFUSED);
    };
    let refuse_glob = |x: &str| -> ! {
        eprintln!("tartaros: --settings: cannot enforce the glob pattern '{x}' on this backend — TartarOS has no general glob engine (Landlock matches by inode). Use a concrete path, the built-in trust-handoff set (.git/.claude/.codex/.mcp.json/…), or the macOS backend for single-* globs. Refusing (apply-fully-or-refuse).");
        exit(EXIT_POLICY_REFUSED);
    };
    // Filesystem. Each pattern is classified after unwrapping single-char classes
    // (a caller.s `.vscod[e]` is really a literal path). Literals map to the generic
    // carve; any-depth patterns must be covered by the trust-handoff set (else
    // refused — a `**` taken literally would protect nothing); single-* globs go to
    // the macOS regex backend, and are refused on Linux.
    // An ALLOW with any kind of glob is refused (we only re-allow concrete paths).
    for x in &s.filesystem.allow_write {
        match classify(x) { (n, PatKind::Literal) => p.writable_roots.push(PathBuf::from(expand_path(&n))), _ => refuse_glob(x) }
    }
    for x in &s.filesystem.allow_read {
        match classify(x) { (n, PatKind::Literal) => p.read_allows.push(PathBuf::from(expand_path(&n))), _ => refuse_glob(x) }
    }
    let map_deny = |x: &str, write: bool, read: bool, p: &mut Policy| {
        let (n, kind) = classify(x);
        match kind {
            PatKind::Literal => {
                let path = PathBuf::from(expand_path(&n));
                if write { p.fs_rules.push(FsRule { path: path.clone(), access: Access::Deny, even_if_absent: true }); }
                if read { p.read_denies.push(path); }
            }
            PatKind::AnyDepth => {
                // The built-in trust-handoff set provides any-depth WRITE protection,
                // so it can satisfy a denyWrite. It does NOT provide read-deny, and
                // TartarOS has no any-depth read engine — so a denyRead (or a combined
                // read+write deny) with a `**` pattern cannot be fully enforced here.
                // Accepting it by equivalence with the handoff (write) set would leave
                // the path READABLE while the settings file asked to deny reads: a
                // silent under-enforcement (POL-01). Refuse instead (apply-fully-or-refuse).
                if read {
                    refuse(&format!(
                        "an any-depth read-deny pattern '{x}' (the trust-handoff set \
                         protects writes, not reads, and there is no any-depth read \
                         rule); use a concrete path under denyRead"
                    ));
                }
                if handoff_covers(&n) {
                    if verbose {
                        eprintln!("tartaros: --settings: '{x}' is covered by the built-in trust-handoff set (write protection) at any depth; applying that.");
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
    //
    // Exception, matching srt: a loopback literal with an explicit port
    // (`localhost:N`, `127.0.0.1:N`, `[::1]:N`) is NOT an external domain — it
    // grants a LOCAL service on that port, exactly like `--port N` (a kernel grant
    // to that loopback port plus a broker loopback-port forward, so the broker
    // never treats it as an external host and rejects it 403). Route those to
    // `local_ports`; send everything else to the egress allow-list. A bare loopback
    // host (no port) or a loopback wildcard (`localhost:*`, `*.localhost`) is
    // unbounded, so refuse it (apply-fully-or-refuse), as srt does.
    let mut domains: Vec<String> = Vec::new();
    for e in &s.network.allowed_domains {
        match classify_loopback_entry(e) {
            LoopbackEntry::Port(n) => p.local_ports.push(n),
            LoopbackEntry::External => domains.push(e.clone()),
            LoopbackEntry::Unbounded => {
                eprintln!(
                    "tartaros: --settings: loopback allowedDomains entry '{e}' is unbounded — \
                     grant a local service by an explicit port (localhost:N / 127.0.0.1:N / [::1]:N), \
                     not a bare host or a wildcard. Refusing (apply-fully-or-refuse)."
                );
                exit(EXIT_POLICY_REFUSED);
            }
        }
    }
    p.allow_domains = domains;
    p.local_ports.sort_unstable();
    p.local_ports.dedup();
    if !s.network.denied_domains.is_empty() {
        refuse("per-domain deny lists");
    }
    // AF_UNIX: macOS Seatbelt allows specific socket paths; the Linux/seccomp
    // backend filters AF_UNIX all-or-nothing (cannot allow one socket by path).
    #[cfg(target_os = "macos")]
    {
        p.allow_unix_socket_paths =
            s.network.allow_unix_sockets.iter().map(|x| PathBuf::from(expand_path(x))).collect();
    }
    #[cfg(target_os = "linux")]
    {
        if s.network.allow_unix_sockets.is_empty() {
            p.deny_unix_sockets = true; // [] = no AF_UNIX at all
        } else {
            eprintln!("tartaros: --settings: cannot allow a specific AF_UNIX socket by path — the Linux/seccomp backend filters AF_UNIX all-or-nothing, not per path. Use an empty list to deny all, or run the macOS (Seatbelt) backend for per-path allow. Refusing (apply-fully-or-refuse).");
            exit(EXIT_POLICY_REFUSED);
        }
    }
    if s.network.allow_local_binding {
        refuse("blanket local binding (grant a concrete port with a port rule instead)");
    }
    // Mach rendezvous (headless browsers): sandbox-runtime writes a name with a
    // trailing `*` meaning a prefix; map it to a global-name-prefix. As in
    // sandbox-runtime, lookups ADD to the curated base of system services (the
    // backend emits it); `--mach-lookup-only` is the strict variant. macOS-only —
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
            exit(EXIT_POLICY_REFUSED);
        }
    }
    // Strict: a settings-driven run is guaranteed-or-abort.
    p.strict = true;
}

/// How a `--settings` `allowedDomains` entry maps into TartarOS's model.
enum LoopbackEntry {
    /// A loopback literal with an explicit port -> a local-service grant (local_ports).
    Port(u16),
    /// A bare loopback host, or a loopback wildcard -> unbounded, must be refused.
    Unbounded,
    /// Any non-loopback host -> an external domain for the egress broker.
    External,
}

/// Classify an srt `allowedDomains` entry. A loopback literal
/// (`localhost` / `127.0.0.1` / `::1`, the last optionally bracketed) with an
/// explicit numeric port is a local-service grant; the same host with no port, or
/// any entry that references loopback through a wildcard, is unbounded; everything
/// else is an external domain.
fn classify_loopback_entry(entry: &str) -> LoopbackEntry {
    // A wildcard that touches loopback (`localhost:*`, `*.localhost`, `127.0.0.1:*`)
    // is never a concrete port grant — refuse before any port parse.
    if entry.contains('*')
        && (entry.contains("localhost") || entry.contains("127.0.0.1") || entry.contains("::1"))
    {
        return LoopbackEntry::Unbounded;
    }
    let (host, port) = split_host_port(entry);
    let is_loopback = matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]");
    if !is_loopback {
        return LoopbackEntry::External;
    }
    match port.and_then(|s| s.parse::<u16>().ok()) {
        Some(n) => LoopbackEntry::Port(n),
        None => LoopbackEntry::Unbounded, // bare loopback host, or a non-numeric port
    }
}

/// Split `host:port` into its parts, handling bracketed IPv6 (`[::1]:N` -> `[::1]`,
/// `N`). Returns the port only when one is present after the host.
fn split_host_port(e: &str) -> (&str, Option<&str>) {
    if e.starts_with('[') {
        if let Some(close) = e.find(']') {
            let host = &e[..=close];
            let port = e[close + 1..].strip_prefix(':');
            return (host, port);
        }
        return (e, None);
    }
    match e.rfind(':') {
        Some(i) => (&e[..i], Some(&e[i + 1..])),
        None => (e, None),
    }
}

/// Parse a numeric flag value or exit with a clear message — never silently fall
/// back to 0, which would turn `--timeout 10m` into "no timeout" (a fail-open).
fn parse_num_or_exit<T: std::str::FromStr>(v: &str, flag: &str) -> T {
    v.parse().unwrap_or_else(|_| {
        eprintln!("error: {flag} expects a number, got '{v}'");
        exit(2);
    })
}

/// Two sinks fed the same events: the egress broker's refusals go to stderr and
/// to the run's --log.
struct Tee<A, B>(A, B);

impl<A: tartaros_core::EffectSink, B: tartaros_core::EffectSink + ?Sized> tartaros_core::EffectSink for Tee<A, Box<B>> {
    fn emit(&mut self, e: &tartaros_core::EffectEvent) {
        self.0.emit(e);
        self.1.emit(e);
    }
}

/// Where and how `--log` writes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LogSpec {
    path: String,
    format: LogFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogFormat {
    Jsonl,
    Otlp,
}

/// The `--log` sink: one of the two formats over an append-mode file. Each line
/// goes out in one write, so the supervisor and the egress broker can append to
/// the same file from their own handles.
enum LogSink {
    Jsonl(tartaros_core::JsonlSink<std::fs::File>),
    Otlp(tartaros_core::OtlpSink<std::fs::File>),
}

impl tartaros_core::EffectSink for LogSink {
    fn emit(&mut self, e: &tartaros_core::EffectEvent) {
        match self {
            LogSink::Jsonl(s) => s.emit(e),
            LogSink::Otlp(s) => s.emit(e),
        }
    }
}

impl LogSpec {
    fn open(&self) -> std::io::Result<LogSink> {
        let f = std::fs::OpenOptions::new().create(true).append(true).open(&self.path)?;
        Ok(match self.format {
            LogFormat::Jsonl => LogSink::Jsonl(tartaros_core::JsonlSink::new(f)),
            LogFormat::Otlp => LogSink::Otlp(tartaros_core::OtlpSink::new(f, tartaros_core::TraceContext::from_env())),
        })
    }
}

/// Build the Policy from --config (if any) + --profile + flags. Returns the
/// policy, the optional --log (path and format), and the selected profile (for its caveat).
fn build_policy(opts: &[String], verbose: bool) -> (Policy, Option<LogSpec>, Option<Profile>) {
    // Shell rc files, .gitconfig and .ripgreprc in a writable root are protected
    // by default, as sandbox-runtime does: a trusted shell or git later runs what
    // the agent planted there. --allow-home-handoff is the dotfiles-repo opt-out.
    let mut p = Policy { network: Some(Network::Denied), protect_home_handoff: true, ..Default::default() };
    let mut profile: Option<Profile> = None;

    // First pass: load --config (a policy file), so flags can override it.
    if let Some(i) = opts.iter().position(|a| a == "--config") {
        let path = opts.get(i + 1).unwrap_or_else(|| { eprintln!("--config needs a path"); exit(2); });
        let text = std::fs::read_to_string(path).unwrap_or_else(|e| { eprintln!("read {path}: {e}"); exit(2); });
        let pf: PolicyFile = toml::from_str(&text).unwrap_or_else(|e| { eprintln!("parse {path}: {e}"); exit(2); });
        p.role = pf.role;
        p.writable_roots = pf.writable_roots.iter().map(|s| PathBuf::from(expand_path(s))).collect();
        p.read_denies = pf.read_denies.iter().map(|s| PathBuf::from(expand_path(s))).collect();
        p.read_allows = pf.read_allows.iter().map(|s| PathBuf::from(expand_path(s))).collect();
        p.fs_rules.extend(pf.write_denies.iter().map(|s| FsRule { path: PathBuf::from(expand_path(s)), access: Access::Deny, even_if_absent: true }));
        p.local_ports = pf.local_ports;
        p.network = Some(if pf.net { Network::Allowed } else { Network::Denied });
        p.deny_unix_sockets = pf.deny_unix_sockets;
        p.isolate_pids = pf.isolate_pids;
        p.isolate_network = pf.isolate_network;
        p.harden_syscalls = pf.harden_syscalls;
        p.strict = pf.strict;
        p.materialize_absent_handoff = pf.materialize_absent_handoff;
        if let Some(on) = pf.protect_home_handoff {
            p.protect_home_handoff = on;
        }
        p.isolate_process_info = pf.isolate_process_info;
        if let Some(b) = pf.broker {
            let _ = BROKER.set(b);
        }
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
    let mut log_format: Option<LogFormat> = None;
    let mut it = opts.iter();
    while let Some(o) = it.next() {
        let mut val = || it.next().cloned().unwrap_or_else(|| { eprintln!("error: {o} needs a value"); exit(2); });
        match o.as_str() {
            "--config" => { let _ = val(); } // handled in the first pass
            "--settings" => { let _ = val(); } // handled above
            "--profile" => { let _ = val(); } // handled in the pre-scan above
            "--role" => p.role = val(),
            "--write" => p.writable_roots.push(PathBuf::from(expand_path(&val()))),
            "--read-deny" => p.read_denies.push(PathBuf::from(expand_path(&val()))),
            "--read-allow" => p.read_allows.push(PathBuf::from(expand_path(&val()))),
            "--write-deny" => p.fs_rules.push(FsRule { path: PathBuf::from(expand_path(&val())), access: Access::Deny, even_if_absent: true }),
            "--port" => p.local_ports.push(val().parse().unwrap_or_else(|_| { eprintln!("bad --port"); exit(2); })),
            "--allow-domain" => p.allow_domains.push(val()),
            "--net" => p.network = Some(Network::Allowed),
            "--deny-unix" => p.deny_unix_sockets = true,
            "--isolate-pids" => p.isolate_pids = true,
            "--isolate-net" => p.isolate_network = true,
            "--seccomp-strict" => p.harden_syscalls = true,
            "--strict" => p.strict = true,
            "--materialize" => p.materialize_absent_handoff = true,
            "--protect-home-handoff" => p.protect_home_handoff = true, // the default since 0.1.0-alpha.7
            "--allow-home-handoff" => p.protect_home_handoff = false,
            "--private-tmp" => p.private_tmp = true,
            "--browser" => p.browser = true,
            "--mach-lookup-only" => p.mach_lookup_only = true,
            "--inherit-env" => p.inherit_env = true,
            "--env" => p.env_passthrough.push(val()),
            "--timeout" => p.timeout = Some(Duration::from_secs(parse_num_or_exit(&val(), "--timeout (seconds)"))),
            "--max-mem" => p.max_memory_bytes = Some(parse_num_or_exit(&val(), "--max-mem (bytes)")),
            "--max-procs" => p.max_processes = Some(parse_num_or_exit(&val(), "--max-procs")),
            "--max-cpu" => p.max_cpu_secs = Some(parse_num_or_exit(&val(), "--max-cpu (seconds)")),
            "--isolate-proc" => p.isolate_process_info = true,
            "--log" => log = Some(val()),
            "--log-format" => log_format = Some(match val().as_str() {
                "jsonl" => LogFormat::Jsonl,
                "otlp" => LogFormat::Otlp,
                other => { eprintln!("error: --log-format is jsonl or otlp, not {other:?}"); exit(2); }
            }),
            other => { eprintln!("unknown option: {other}"); exit(2); }
        }
    }
    if log_format.is_some() && log.is_none() {
        eprintln!("error: --log-format needs --log FILE");
        exit(2);
    }
    let log = log.map(|path| LogSpec { path, format: log_format.unwrap_or(LogFormat::Jsonl) });
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
        let base = if p.mach_lookup_only { "only these" } else { "curated base +" };
        println!("macOS Mach lookup ({base} prefix): {}", p.allow_mach_lookup.join(", "));
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
        // Show only NAMES, never values: a `--env KEY=VALUE` carries a literal secret,
        // and explain output lands in logs/CI. Distinguish inherited (KEY) from
        // explicitly-set (KEY=…, value redacted).
        if !p.env_passthrough.is_empty() {
            let shown: Vec<String> = p
                .env_passthrough
                .iter()
                .map(|e| match e.split_once('=') {
                    Some((k, _)) => format!("{k}=<redacted>"),
                    None => format!("{e} (inherited)"),
                })
                .collect();
            println!("  + explicit --env: {}", shown.join(", "));
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
            // writable root (a trust-handoff or explicit deny sits below, existing
            // or not). This is LESS permission, not a contract break — a consumer
            // surfaces it as a notice. The backend answers from the carve the run
            // uses, so the warning is said exactly when the run will refuse.
            for w in tartaros_linux::roots_without_new_entries(p) {
                let mut named: Vec<String> = w.denies.iter().take(3).map(|d| d.display().to_string()).collect();
                if w.denies.len() > 3 { named.push(format!("{} more", w.denies.len() - 3)); }
                println!(
                    "warning: on Linux, new entries cannot be created directly in {} (Landlock cannot grant a directory minus what is below it: {}); existing files and subdirectories are writable. Write into a subdirectory instead. The read-only bind mounts that lift this are not used: {}.",
                    w.root.display(),
                    named.join(", "),
                    w.because
                );
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn run(policy: &Policy, cmd: &[String], log: Option<&LogSpec>) -> i32 {
    run_common(&tartaros_linux::LandlockBackend, policy, cmd, log, true)
}

#[cfg(target_os = "macos")]
fn run(policy: &Policy, cmd: &[String], log: Option<&LogSpec>) -> i32 {
    run_common(&tartaros_macos::SeatbeltBackend, policy, cmd, log, true)
}

/// Shared run path (both OS): `--log` goes through `run_observed`, which uses the
/// SAME supervisor (timeout, limits, reaping) as `run` — enabling the log never
/// changes the enforcement guarantees (review P0). `net` selects whether to add
/// the network collector.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_common<B>(be: &B, policy: &Policy, cmd: &[String], log: Option<&LogSpec>, net: bool) -> i32
where
    B: RunObserved,
{
    use tartaros_collect::{FileCollector, NetworkCollector, ProcessCollector, SecretCollector};
    use tartaros_core::{Collector, FilterSink, RecordMode};
    // Refuse an unenforceable policy before anything starts, with its own exit
    // code, so a caller can tell "refused your policy" from "could not start".
    if let Err(e) = be.validate(policy) {
        eprintln!("tartaros: {}", e.reason);
        return EXIT_POLICY_REFUSED;
    }
    match log {
        Some(spec) => {
            let s = match spec.open() {
                Ok(s) => s,
                Err(e) => { eprintln!("tartaros: cannot open log {}: {e}", spec.path); return 1; }
            };
            let mut sink = FilterSink::new(s, RecordMode::Boundary);
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

#[cfg(target_os = "windows")]
fn run(policy: &Policy, cmd: &[String], log: Option<&LogSpec>) -> i32 {
    use tartaros_core::Backend;
    // The effect log goes through collectors that sample the process tree; there
    // are none for Windows yet. Enabling the log must never change what is
    // enforced, so rather than silently ignore --log we refuse it (fail-closed).
    if log.is_some() {
        eprintln!("tartaros: --log is not available on the Windows backend yet (no effect-log collectors); run without it.");
        return 2;
    }
    if let Err(e) = tartaros_windows::WindowsBackend.validate(policy) {
        eprintln!("tartaros: {}", e.reason);
        return EXIT_POLICY_REFUSED;
    }
    match tartaros_windows::WindowsBackend.run(policy, cmd) {
        Ok(o) => o.exit_code,
        Err(e) => {
            eprintln!("tartaros: {}", e.reason);
            1
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn run(_policy: &Policy, _cmd: &[String], _log: Option<&LogSpec>) -> i32 {
    eprintln!("tartaros: unsupported OS");
    1
}

#[cfg(test)]
mod tests {
    use super::{classify_loopback_entry, LoopbackEntry};

    fn port(e: &str) -> Option<u16> {
        match classify_loopback_entry(e) {
            LoopbackEntry::Port(n) => Some(n),
            _ => None,
        }
    }
    fn is_unbounded(e: &str) -> bool {
        matches!(classify_loopback_entry(e), LoopbackEntry::Unbounded)
    }
    fn is_external(e: &str) -> bool {
        matches!(classify_loopback_entry(e), LoopbackEntry::External)
    }

    #[test]
    fn loopback_literal_with_port_becomes_a_local_port() {
        assert_eq!(port("localhost:18769"), Some(18769));
        assert_eq!(port("127.0.0.1:18769"), Some(18769));
        assert_eq!(port("[::1]:18769"), Some(18769));
    }

    #[test]
    fn non_loopback_stays_an_external_domain() {
        assert!(is_external("example.com"));
        assert!(is_external("api.example.com:443"));
        // A non-loopback wildcard is a normal domain pattern, not refused.
        assert!(is_external("*.github.com"));
        // A real external IPv6 literal is not loopback.
        assert!(is_external("[2001:db8::1]:443"));
    }

    #[test]
    fn bare_loopback_or_wildcard_is_refused() {
        assert!(is_unbounded("localhost"));
        assert!(is_unbounded("127.0.0.1"));
        assert!(is_unbounded("[::1]"));
        assert!(is_unbounded("localhost:*"));
        assert!(is_unbounded("*.localhost"));
        assert!(is_unbounded("127.0.0.1:*"));
    }
}
