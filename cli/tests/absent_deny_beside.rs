//! An explicit write deny on a path that does not exist yet (seisin's
//! `never_writes = ["app/.git/index.lock"]`) holds, and the rest of the directory
//! takes new files. On Linux it forced the carve before 0.1.0-alpha.20, and a
//! directory holding a withheld entry takes no new ones there: the role could not
//! create `app/ok.txt` in its own territory. With a mount namespace it is now held
//! by a placeholder, as an absent handoff path is, and removed after the run.
//! Without one (the carve) the limit stays, as docs/limits.md says.
#![cfg(unix)]

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_tartaros");

fn has_mount_namespace() -> bool {
    if cfg!(target_os = "macos") {
        return true; // Seatbelt: no carve, nothing to place
    }
    Command::new("unshare").args(["-Urm", "true"]).status().is_ok_and(|s| s.success())
        || Command::new("id").arg("-u").output().is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
}

#[test]
fn an_absent_deny_holds_and_its_directory_still_takes_new_files() {
    let dir = std::env::temp_dir().join(format!("tartaros-absent-beside-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("app/.git")).unwrap();
    let dir = std::fs::canonicalize(&dir).unwrap();
    let lock = dir.join("app/.git/index.lock");
    let script = format!(
        "(echo x > '{}') 2>/dev/null && echo LOCK; (echo x > '{}') 2>/dev/null && echo OK; true",
        lock.display(),
        dir.join("app/ok.txt").display()
    );
    let out = Command::new(BIN)
        .arg("run").arg("--write").arg(&dir).arg("--write-deny").arg(&lock)
        .args(["--", "sh", "-c", &script])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(!stdout.contains("LOCK"), "the denied path was created: {stdout}");
    if has_mount_namespace() {
        assert!(stdout.contains("OK"), "a new file beside it was refused: {stdout}");
    }
    // Nothing is left where the deny was.
    assert!(!lock.exists(), "a placeholder was left behind");
    let _ = std::fs::remove_dir_all(dir);
}
