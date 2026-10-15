//! Run one command under the Windows backend, stdio inherited — the backend's
//! equivalent of `tartaros run`, for debugging on a Windows host.
//!
//! ```text
//! run_backend [--write DIR]... [--read DIR]... [--read-deny DIR]... [--env KEY[=VALUE]]... [--inherit-env] -- CMD [ARGS]...
//! ```

use std::path::PathBuf;
use tartaros_core::{Backend, Policy};

fn main() {
    let mut p = Policy::default();
    let mut it = std::env::args().skip(1);
    let mut cmd = Vec::new();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--write" => p.writable_roots.push(PathBuf::from(it.next().expect("--write DIR"))),
            "--read" => p.read_allows.push(PathBuf::from(it.next().expect("--read DIR"))),
            "--read-deny" => p.read_denies.push(PathBuf::from(it.next().expect("--read-deny DIR"))),
            "--inherit-env" => p.inherit_env = true,
            "--env" => p.env_passthrough.push(it.next().expect("--env KEY[=VALUE]")),
            "--" => {
                cmd = it.collect();
                break;
            }
            other => panic!("unknown flag {other}"),
        }
    }
    match tartaros_windows::WindowsBackend.run(&p, &cmd) {
        Ok(o) => {
            eprintln!("[run_backend] exit {}", o.exit_code);
            std::process::exit(o.exit_code);
        }
        Err(e) => {
            eprintln!("[run_backend] error: {}", e.reason);
            std::process::exit(3);
        }
    }
}
