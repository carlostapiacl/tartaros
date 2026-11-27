//! AF_UNIX is denied by default on Linux, and `--allow-unix` opens it.
//!
//! Landlock cannot scope a unix socket by path, so a run that can create one can
//! reach any daemon socket on the host: the session bus starts an unconfined
//! `systemd-run --user` (measured 2026-11-27 on Ubuntu 24.04). socketpair() is
//! not a socket(AF_UNIX) call and keeps working, so multiprocessing pipes do too.
#![cfg(target_os = "linux")]

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_tartaros");

fn landlock() -> bool {
    std::fs::read_to_string("/sys/kernel/security/lsm").map(|s| s.contains("landlock")).unwrap_or(false)
}

fn run(extra: &[&str], py: &str) -> bool {
    let dir = std::env::temp_dir().join(format!("tartaros-unixdef-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let dir = dir.canonicalize().unwrap();
    let mut args = vec!["run", "--write", dir.to_str().unwrap()];
    args.extend_from_slice(extra);
    args.extend_from_slice(&["--", "python3", "-c", py]);
    Command::new(BIN).args(&args).status().unwrap().success()
}

const UNIX: &str = "import socket; socket.socket(socket.AF_UNIX)";
const PAIR: &str = "import socket; socket.socketpair()";

#[test]
fn af_unix_is_denied_by_default() {
    if !landlock() {
        eprintln!("skip: no Landlock");
        return;
    }
    assert!(!run(&[], UNIX), "a default run created an AF_UNIX socket");
    assert!(run(&[], PAIR), "socketpair() must keep working by default");
}

#[test]
fn allow_unix_opens_it() {
    if !landlock() {
        eprintln!("skip: no Landlock");
        return;
    }
    assert!(run(&["--allow-unix"], UNIX), "--allow-unix did not open AF_UNIX");
}
