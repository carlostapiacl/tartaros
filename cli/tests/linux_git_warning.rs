//! `run` warns that `git add` will fail exactly when the run cannot create an
//! entry in the repository's `.git` (Linux).
//!
//! Without a mount namespace the Landlock carve withholds `.git`, because its
//! hooks and config are denied, so git cannot write `.git/index.lock`. Measured
//! on Ubuntu 24.04 without root (2026-11-27): `explain` said so, `run` did not,
//! and the first `git add` failed. This drives the real binary on whichever host
//! it runs and checks that the warning and the kernel agree.
#![cfg(target_os = "linux")]

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_tartaros");

#[test]
fn git_warning_matches_what_the_run_can_do() {
    if !std::fs::read_to_string("/sys/kernel/security/lsm").map(|s| s.contains("landlock")).unwrap_or(false) {
        eprintln!("skip: no Landlock");
        return;
    }
    let repo = std::env::temp_dir().join(format!("tartaros-gitwarn-{}", std::process::id()));
    std::fs::create_dir_all(repo.join(".git/hooks")).unwrap();
    std::fs::write(repo.join(".git/config"), "[core]\n").unwrap();
    let repo = repo.canonicalize().unwrap();
    let out = Command::new(BIN)
        .args(["run", "--write", repo.to_str().unwrap(), "--", "sh", "-c", "echo x > .git/index.lock"])
        .current_dir(&repo)
        .output()
        .unwrap();
    let warned = String::from_utf8_lossy(&out.stderr).contains("git add/commit will fail");
    assert_eq!(
        warned,
        !out.status.success(),
        "warning ({warned}) disagrees with the run (exit {:?}): {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
}
