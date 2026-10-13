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
use std::path::PathBuf;
use std::process::exit;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(|s| s.as_str()) != Some("run") {
        eprintln!("usage: seisin-sandbox run [options] -- <command> [args...]");
        exit(2);
    }
    let rest = &args[1..];
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

    let mut p = Policy { network: Some(Network::Denied), ..Default::default() };
    let mut log: Option<String> = None;
    let mut it = opts.iter();
    while let Some(o) = it.next() {
        let mut val = || it.next().cloned().unwrap_or_else(|| { eprintln!("error: {o} needs a value"); exit(2); });
        match o.as_str() {
            "--role" => p.role = val(),
            "--write" => p.writable_roots.push(PathBuf::from(val())),
            "--read-deny" => p.read_denies.push(PathBuf::from(val())),
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
    if p.writable_roots.is_empty() {
        eprintln!("warning: no --write roots; the command cannot write anywhere");
    }

    let code = run(&p, &cmd, log.as_deref());
    exit(code);
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
    if log.is_some() {
        eprintln!("seisin-sandbox: --log (effect collectors) is Linux-only for now");
    }
    match seisin_sandbox_macos::SeatbeltBackend.run(policy, cmd) {
        Ok(o) => o.exit_code,
        Err(e) => { eprintln!("seisin-sandbox: {}", e.reason); 1 }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn run(_policy: &Policy, _cmd: &[String], _log: Option<&str>) -> i32 {
    eprintln!("seisin-sandbox: unsupported OS");
    1
}
