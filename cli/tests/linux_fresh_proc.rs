//! With a PID namespace (on by default where the host allows it) and any read
//! deny, the run can still read its own /proc.
//!
//! The read carve opens its rules on the host's /proc before the namespace mounts
//! a fresh one, so the fresh /proc was unreadable: Node's process.memoryUsage()
//! and os.cpus() failed, and so did tools that read /proc/self/stat (measured
//! 2026-11-27 on Kali, tartaros 0.1.0-alpha.26).
#![cfg(target_os = "linux")]

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_tartaros");
const READS: &str = "cat /proc/self/statm /proc/self/status /proc/stat /proc/cpuinfo > /dev/null";

fn landlock() -> bool {
    std::fs::read_to_string("/sys/kernel/security/lsm")
        .map(|s| s.contains("landlock"))
        .unwrap_or(false)
}

fn run(extra: &[&str], script: &str) -> std::process::Output {
    let dir = tempfile_dir("work");
    let mut args = vec!["run", "--isolate-pids", "--write", dir.to_str().unwrap()];
    args.extend_from_slice(extra);
    args.extend_from_slice(&["--", "sh", "-c", script]);
    Command::new(BIN).args(&args).output().unwrap()
}

fn tempfile_dir(name: &str) -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("tartaros-fresh-proc-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.canonicalize().unwrap()
}

#[test]
fn own_proc_stays_readable_with_a_read_deny() {
    if !landlock() {
        eprintln!("skip: no Landlock");
        return;
    }
    let secret = tempfile_dir("secret");
    std::fs::write(secret.join("key"), "s3cret").unwrap();
    let out = run(&["--read-deny", secret.to_str().unwrap()], READS);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let peek = run(
        &["--read-deny", secret.to_str().unwrap()],
        &format!("cat {}/key", secret.display()),
    );
    assert!(!peek.status.success(), "the read deny stopped holding");
}
