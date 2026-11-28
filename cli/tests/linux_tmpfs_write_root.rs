//! A writable root on a tmpfs works, with its protected paths still read-only.
//!
//! Inside the user namespace the nosuid/nodev flags of a mount are locked, and the
//! read-only bind of a protected path (`.git/hooks` in a root) dropped them, so the
//! kernel refused the remount and every run with `--write` under a tmpfs `/tmp`
//! failed with "spawn: Operation not permitted" (measured 2026-11-27 on Kali).
#![cfg(target_os = "linux")]

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_tartaros");

fn landlock() -> bool {
    std::fs::read_to_string("/sys/kernel/security/lsm").map(|s| s.contains("landlock")).unwrap_or(false)
}

/// A tmpfs mount with nosuid or nodev the test can write in, if the host has one.
fn tmpfs_dir() -> Option<std::path::PathBuf> {
    let mounts = std::fs::read_to_string("/proc/self/mounts").ok()?;
    let uid = unsafe { libc::getuid() };
    for line in mounts.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 || f[2] != "tmpfs" || !(f[3].contains("nosuid") || f[3].contains("nodev")) {
            continue;
        }
        for base in ["/tmp".to_string(), format!("/run/user/{uid}")] {
            if f[1] == base {
                let dir = std::path::Path::new(&base).join(format!("tartaros-tmpfs-root-{}", std::process::id()));
                if std::fs::create_dir_all(dir.join(".git/hooks")).is_ok() {
                    return dir.canonicalize().ok();
                }
            }
        }
    }
    None
}

#[test]
fn write_root_on_a_tmpfs_runs_and_keeps_git_hooks_read_only() {
    if !landlock() {
        eprintln!("skip: no Landlock");
        return;
    }
    let Some(dir) = tmpfs_dir() else {
        eprintln!("skip: no writable nosuid/nodev tmpfs");
        return;
    };
    let root = dir.to_str().unwrap();
    let run = |script: &str| Command::new(BIN).current_dir(&dir).args(["run", "--write", root, "--", "sh", "-c", script]).output().unwrap();

    let out = run("echo ok > inside.txt && cat inside.txt");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "ok");

    let planted = run("echo x > .git/hooks/pre-commit; echo reached");
    assert!(String::from_utf8_lossy(&planted.stdout).contains("reached"), "{}", String::from_utf8_lossy(&planted.stderr));
    assert!(!dir.join(".git/hooks/pre-commit").exists(), "a hook was planted in a tmpfs root");
    let _ = std::fs::remove_dir_all(&dir);
}

/// /dev/shm is replaced by a private tmpfs in the run, which would hide the
/// read-only binds of a root inside it. Whatever the host allows, a hook must
/// never be planted there.
#[test]
fn write_root_in_dev_shm_never_loses_its_protected_paths() {
    if !landlock() {
        eprintln!("skip: no Landlock");
        return;
    }
    let dir = std::path::Path::new("/dev/shm").join(format!("tartaros-shm-root-{}", std::process::id()));
    if std::fs::create_dir_all(dir.join(".git/hooks")).is_err() {
        eprintln!("skip: /dev/shm is not writable");
        return;
    }
    let out = Command::new(BIN)
        .current_dir(&dir)
        .args(["run", "--write", dir.to_str().unwrap(), "--", "sh", "-c", "echo x > .git/hooks/pre-commit"])
        .output()
        .unwrap();
    let planted = dir.join(".git/hooks/pre-commit").exists();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(!planted, "a hook was planted in a /dev/shm root: {}", String::from_utf8_lossy(&out.stderr));
}
