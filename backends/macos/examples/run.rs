//! Run a command confined by a default policy over the current directory.
//! `cargo run -q -p tartaros-macos --example run -- <cmd> [args...]`
//!
//! writable root = cwd, network denied, process-info isolated. Exits with the
//! command's exit code. Handy for ad-hoc checks and measurements.

use tartaros_core::{Backend, Network, Policy};
use tartaros_macos::SeatbeltBackend;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: run -- <command> [args...]");
        std::process::exit(2);
    }
    let cwd = std::env::current_dir().expect("cwd");
    let policy = Policy {
        writable_roots: vec![cwd],
        network: Some(Network::Denied),
        isolate_process_info: true,
        ..Default::default()
    };
    match SeatbeltBackend.run(&policy, &args) {
        Ok(out) => std::process::exit(out.exit_code),
        Err(e) => {
            eprintln!("run error: {}", e.reason);
            std::process::exit(1);
        }
    }
}
