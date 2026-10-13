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
//!   --net                  allow all network (default: denied)
//!   --deny-unix            deny AF_UNIX sockets (Linux, seccomp)
//!   --isolate-pids         run in a private PID+mount namespace (Linux; hides host processes)
//!   --isolate-net          run in an empty network namespace (Linux; no egress at all, loopback only)
//!   --seccomp-strict       deny dangerous syscalls to shrink kernel attack surface (Linux)
//!   --strict               a requested guarantee that cannot be installed aborts the run
//!   --materialize          pre-create absent trust-handoff placeholders (Linux)
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
            exit(if args.first().is_none() { 2 } else { 0 });
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
  --net                  allow all network (default: denied)

HARDENING (Linux; the hostile/multi-tenant profiles set these):
  --isolate-pids         private PID+mount namespace (hide host processes)
  --isolate-net          empty network namespace (no egress, any protocol)
  --seccomp-strict       deny dangerous syscalls (shrink kernel attack surface)
  --strict               a requested guarantee that cannot be installed aborts the run
  --deny-unix            deny AF_UNIX sockets
  --isolate-proc         deny reads of other processes' /proc
  --materialize          pre-create absent trust-handoff placeholders

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
    let (p, log, profile) = build_policy(opts);
    if p.writable_roots.is_empty() {
        eprintln!("warning: no --write roots; the command cannot write anywhere");
    }
    // Print the profile's honest caveat before running — a tier must never
    // silently overclaim (esp. multi-tenant on a shared kernel).
    if let Some(pr) = profile {
        if let Some(c) = pr.caveat() {
            eprintln!("tartaros: profile {} — {}", pr.name(), c);
        }
    }
    exit(run(&p, &cmd, log.as_deref()));
}

fn cmd_explain(opts: &[String]) -> ! {
    let (p, _, profile) = build_policy(opts);
    if let Some(pr) = profile {
        println!("profile: {} — {}", pr.name(), pr.tier());
        if let Some(c) = pr.caveat() {
            println!("profile caveat: {c}");
        }
        println!();
    }
    explain(&p);
    exit(0);
}

/// sandbox-runtime settings schema (the subset we read). An adapter maps it onto
/// the generic Policy; anything we cannot enforce makes the launch refuse.
#[derive(Deserialize, Default)]
struct SandboxSettings {
    #[serde(default)]
    filesystem: SandboxFs,
    #[serde(default)]
    network: SandboxNet,
}
#[derive(Deserialize, Default)]
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
struct SandboxNet {
    #[serde(default, rename = "allowedDomains")]
    allowed_domains: Vec<String>,
    #[serde(default, rename = "deniedDomains")]
    denied_domains: Vec<String>,
    #[serde(default, rename = "allowUnixSockets")]
    allow_unix_sockets: Vec<String>,
    #[serde(default, rename = "allowLocalBinding")]
    allow_local_binding: bool,
}

/// Apply a sandbox-runtime settings file strictly: map the fields we can enforce
/// onto the generic policy, and REFUSE (exit) on any field we cannot guarantee,
/// rather than running under-enforced. "Apply fully or do not start."
fn apply_settings_file(p: &mut Policy, path: &str) {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| { eprintln!("read {path}: {e}"); exit(2); });
    let s: SandboxSettings = serde_json::from_str(&text).unwrap_or_else(|e| { eprintln!("parse {path}: {e}"); exit(2); });
    let refuse = |what: &str| -> ! {
        eprintln!("tartaros: --settings: cannot guarantee {what} on this backend; refusing to run (apply-fully-or-refuse).");
        exit(2);
    };
    // Filesystem: fully expressible with the generic carve.
    p.writable_roots = s.filesystem.allow_write.iter().map(|x| PathBuf::from(expand(x))).collect();
    p.read_denies = s.filesystem.deny_read.iter().map(|x| PathBuf::from(expand(x))).collect();
    p.read_allows = s.filesystem.allow_read.iter().map(|x| PathBuf::from(expand(x))).collect();
    p.fs_rules.extend(s.filesystem.deny_write.iter().map(|x| FsRule { path: PathBuf::from(expand(x)), access: Access::Deny, even_if_absent: true }));
    // Network: we default-deny. Anything we cannot enforce in-sandbox is refused.
    p.network = Some(Network::Denied);
    if !s.network.allowed_domains.is_empty() {
        refuse("per-domain egress (needs the broker; not wired into `run` yet)");
    }
    if !s.network.denied_domains.is_empty() {
        refuse("per-domain deny lists");
    }
    if !s.network.allow_unix_sockets.is_empty() {
        refuse("a specific AF_UNIX socket (seccomp is all-or-nothing on Linux)");
    }
    if s.network.allow_local_binding {
        refuse("blanket local binding (grant a concrete port with a port rule instead)");
    }
    // Strict: a settings-driven run is guaranteed-or-abort.
    p.strict = true;
}

/// Build the Policy from --config (if any) + --profile + flags. Returns the
/// policy, the optional --log path, and the selected profile (for its caveat).
fn build_policy(opts: &[String]) -> (Policy, Option<String>, Option<Profile>) {
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
        apply_settings_file(&mut p, path);
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
            "--net" => p.network = Some(Network::Allowed),
            "--deny-unix" => p.deny_unix_sockets = true,
            "--isolate-pids" => p.isolate_pids = true,
            "--isolate-net" => p.isolate_network = true,
            "--seccomp-strict" => p.harden_syscalls = true,
            "--strict" => p.strict = true,
            "--materialize" => p.materialize_absent_handoff = true,
            "--timeout" => p.timeout = Some(Duration::from_secs(val().parse().unwrap_or(0))),
            "--max-mem" => p.max_memory_bytes = Some(val().parse().unwrap_or(0)),
            "--max-procs" => p.max_processes = Some(val().parse().unwrap_or(0)),
            "--max-cpu" => p.max_cpu_secs = Some(val().parse().unwrap_or(0)),
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
    println!("deny AF_UNIX sockets: {}", p.deny_unix_sockets);
    println!("isolate PID namespace: {}", p.isolate_pids);
    println!("isolate network (no egress): {}", p.isolate_network);
    println!("seccomp attack-surface reduction: {}", p.harden_syscalls);
    println!("strict (guaranteed-or-abort): {}", p.strict);
    println!("isolate /proc (env reads): {}", p.isolate_process_info);
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
    println!("\ntrust-handoff protected (deny write, any depth):");
    for r in p.trust_handoff_rules() { println!("  ! {}", r.path.display()); }

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
        println!("\n--- Linux Landlock allow-lists (based on the current filesystem) ---");
        println!("write (carved):");
        for a in p.linux_write_allowlist() { println!("  w {}", a.display()); }
        println!("read (carved):");
        for a in p.linux_read_allowlist() { println!("  r {}", a.display()); }
        println!("note: writes grant write-only; reads are governed by the read carve.");
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
    use tartaros_collect::{NetworkCollector, ProcessCollector, SecretCollector};
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
