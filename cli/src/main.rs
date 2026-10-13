//! seisin-sandbox CLI — run a command confined by a policy, on the OS backend.
//!
//! Usage:
//!   seisin-sandbox run [options] -- <command> [args...]
//!
//! Options:
//!   --role NAME            label for effect-log attribution
//!   --write DIR            a writable root (repeatable)
//!   --read-deny DIR        deny reads of this path (repeatable; secrets)
//!   --port N               allow loopback TCP to this port (repeatable)
//!   --net                  allow all network (default: denied)
//!   --deny-unix            deny AF_UNIX sockets (Linux, seccomp)
//!   --materialize          pre-create absent trust-handoff placeholders (Linux)
//!   --timeout SECS         kill the process group after SECS (exit 124)
//!   --max-mem BYTES        address-space limit
//!   --max-procs N          process limit
//!   --log FILE             write the effect log (JSON Lines) here (Linux)
//!
//! Exit code is the command's (128+signal on signal death, 124 on timeout).

use seisin_sandbox_core::{Backend, Network, Policy};
use serde::Deserialize;
use std::path::PathBuf;
use std::process::exit;
use std::time::Duration;

/// A policy file (TOML) — declare a role's confinement once, apply it on any OS.
/// Flags on the command line override / append to it.
#[derive(Deserialize, Default)]
struct PolicyFile {
    #[serde(default)]
    role: String,
    #[serde(default)]
    writable_roots: Vec<String>,
    #[serde(default)]
    read_denies: Vec<String>,
    #[serde(default)]
    local_ports: Vec<u16>,
    #[serde(default)]
    net: bool,
    #[serde(default)]
    deny_unix_sockets: bool,
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
        _ => {
            eprintln!("usage:\n  seisin-sandbox run [options] -- <command> [args...]\n  seisin-sandbox explain [options]   # print what a policy grants, without running");
            exit(2);
        }
    }
}

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
    let (p, log) = build_policy(opts);
    if p.writable_roots.is_empty() {
        eprintln!("warning: no --write roots; the command cannot write anywhere");
    }
    exit(run(&p, &cmd, log.as_deref()));
}

fn cmd_explain(opts: &[String]) -> ! {
    let (p, _) = build_policy(opts);
    explain(&p);
    exit(0);
}

/// Build the Policy from --config (if any) + flags. Returns the policy and the
/// optional --log path.
fn build_policy(opts: &[String]) -> (Policy, Option<String>) {
    let mut p = Policy { network: Some(Network::Denied), ..Default::default() };

    // First pass: load --config (a policy file), so flags can override it.
    if let Some(i) = opts.iter().position(|a| a == "--config") {
        let path = opts.get(i + 1).unwrap_or_else(|| { eprintln!("--config needs a path"); exit(2); });
        let text = std::fs::read_to_string(path).unwrap_or_else(|e| { eprintln!("read {path}: {e}"); exit(2); });
        let pf: PolicyFile = toml::from_str(&text).unwrap_or_else(|e| { eprintln!("parse {path}: {e}"); exit(2); });
        p.role = pf.role;
        p.writable_roots = pf.writable_roots.iter().map(|s| PathBuf::from(expand(s))).collect();
        p.read_denies = pf.read_denies.iter().map(|s| PathBuf::from(expand(s))).collect();
        p.local_ports = pf.local_ports;
        p.network = Some(if pf.net { Network::Allowed } else { Network::Denied });
        p.deny_unix_sockets = pf.deny_unix_sockets;
        p.materialize_absent_handoff = pf.materialize_absent_handoff;
        p.isolate_process_info = pf.isolate_process_info;
        p.timeout = pf.timeout_secs.map(Duration::from_secs);
        p.max_memory_bytes = pf.max_memory_bytes;
        p.max_processes = pf.max_processes;
    }

    let mut log: Option<String> = None;
    let mut it = opts.iter();
    while let Some(o) = it.next() {
        let mut val = || it.next().cloned().unwrap_or_else(|| { eprintln!("error: {o} needs a value"); exit(2); });
        match o.as_str() {
            "--config" => { let _ = val(); } // handled in the first pass
            "--role" => p.role = val(),
            "--write" => p.writable_roots.push(PathBuf::from(expand(&val()))),
            "--read-deny" => p.read_denies.push(PathBuf::from(expand(&val()))),
            "--port" => p.local_ports.push(val().parse().unwrap_or_else(|_| { eprintln!("bad --port"); exit(2); })),
            "--net" => p.network = Some(Network::Allowed),
            "--deny-unix" => p.deny_unix_sockets = true,
            "--materialize" => p.materialize_absent_handoff = true,
            "--timeout" => p.timeout = Some(Duration::from_secs(val().parse().unwrap_or(0))),
            "--max-mem" => p.max_memory_bytes = Some(val().parse().unwrap_or(0)),
            "--max-procs" => p.max_processes = Some(val().parse().unwrap_or(0)),
            "--isolate-proc" => p.isolate_process_info = true,
            "--log" => log = Some(val()),
            other => { eprintln!("unknown option: {other}"); exit(2); }
        }
    }
    (p, log)
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
    println!("isolate /proc (env reads): {}", p.isolate_process_info);
    if let Some(t) = p.timeout { println!("timeout: {}s", t.as_secs()); }
    if let Some(m) = p.max_memory_bytes { println!("max memory: {m} bytes"); }
    println!("\nwritable roots:");
    for r in &p.writable_roots { println!("  + {}", r.display()); }
    println!("\nread-denied (secrets):");
    for r in &p.read_denies { println!("  - {}", r.display()); }
    println!("\ntrust-handoff protected (deny write, any depth):");
    for r in p.trust_handoff_rules() { println!("  ! {}", r.path.display()); }

    #[cfg(target_os = "macos")]
    {
        println!("\n--- macOS Seatbelt profile ---");
        println!("{}", seisin_sandbox_macos::compile_profile(p));
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
    use seisin_sandbox_collect::{observe_until_exit, NetworkCollector, ProcessCollector, SecretCollector};
    use seisin_sandbox_core::{Collector, FilterSink, JsonlSink, RecordMode};

    let be = seisin_sandbox_linux::LandlockBackend;
    match log {
        Some(path) => {
            // spawn + observe so we can write the effect log of this real run.
            let mut child = match be.spawn(policy, cmd) {
                Ok(c) => c,
                Err(e) => { eprintln!("seisin-sandbox: {}", e.reason); return 1; }
            };
            let pid = child.id();
            let mut collectors: Vec<Box<dyn Collector>> = vec![
                Box::new(NetworkCollector::for_policy(pid, policy)),
                Box::new(SecretCollector::for_policy(pid, policy)),
                Box::new(ProcessCollector::for_policy(pid, policy)),
            ];
            let file = std::fs::OpenOptions::new().create(true).append(true).open(path);
            match file {
                Ok(f) => {
                    let mut sink = FilterSink::new(JsonlSink::new(f), RecordMode::Boundary);
                    observe_until_exit(&mut child, &mut collectors, &mut sink, Duration::from_millis(80))
                }
                Err(e) => { eprintln!("seisin-sandbox: cannot open log {path}: {e}"); let _ = child.wait(); 1 }
            }
        }
        None => match be.run(policy, cmd) {
            Ok(o) => o.exit_code,
            Err(e) => { eprintln!("seisin-sandbox: {}", e.reason); 1 }
        },
    }
}

#[cfg(target_os = "macos")]
fn run(policy: &Policy, cmd: &[String], log: Option<&str>) -> i32 {
    use seisin_sandbox_collect::{observe_until_exit, NetworkCollector, ProcessCollector, SecretCollector};
    use seisin_sandbox_core::{Collector, FilterSink, JsonlSink, RecordMode};
    let be = seisin_sandbox_macos::SeatbeltBackend;
    match log {
        Some(path) => {
            // macOS collectors sample via lsof/ps (secret + process; network TBD).
            let mut child = match be.spawn(policy, cmd) {
                Ok(c) => c,
                Err(e) => { eprintln!("seisin-sandbox: {}", e.reason); return 1; }
            };
            let pid = child.id();
            let mut collectors: Vec<Box<dyn Collector>> = vec![
                Box::new(NetworkCollector::for_policy(pid, policy)),
                Box::new(SecretCollector::for_policy(pid, policy)),
                Box::new(ProcessCollector::for_policy(pid, policy)),
            ];
            match std::fs::OpenOptions::new().create(true).append(true).open(path) {
                Ok(f) => {
                    let mut sink = FilterSink::new(JsonlSink::new(f), RecordMode::Boundary);
                    observe_until_exit(&mut child, &mut collectors, &mut sink, Duration::from_millis(120))
                }
                Err(e) => { eprintln!("seisin-sandbox: cannot open log {path}: {e}"); let _ = child.wait(); 1 }
            }
        }
        None => match be.run(policy, cmd) {
            Ok(o) => o.exit_code,
            Err(e) => { eprintln!("seisin-sandbox: {}", e.reason); 1 }
        },
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn run(_policy: &Policy, _cmd: &[String], _log: Option<&str>) -> i32 {
    eprintln!("seisin-sandbox: unsupported OS");
    1
}
