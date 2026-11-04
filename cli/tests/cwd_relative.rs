//! A relative path from the working directory is written where it says. Under
//! the Linux bind-mount strategy (root, or a user namespace) the inherited cwd
//! pointed into the mount below the pins, which the seal makes read-only, so
//! before 0.1.0-alpha.20 `echo x > a/f` from inside a writable root failed with
//! EROFS while the same write by absolute path went through.
#![cfg(unix)]

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_tartaros");

#[test]
fn a_relative_write_from_inside_a_writable_root_goes_through() {
    let dir = std::env::temp_dir().join(format!("tartaros-cwd-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("a")).unwrap();
    std::fs::create_dir_all(dir.join(".git/hooks")).unwrap();
    std::fs::write(dir.join("a/f"), "before\n").unwrap();
    let out = Command::new(BIN)
        .current_dir(&dir)
        .arg("run").arg("--write").arg(&dir)
        .args(["--", "sh", "-c", "echo after > a/f && echo new > a/g && echo x > .git/hooks/h; echo rc=$?"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(std::fs::read_to_string(dir.join("a/f")).unwrap(), "after\n", "{stdout} {}", String::from_utf8_lossy(&out.stderr));
    assert!(dir.join("a/g").exists());
    // ...and what is protected stays protected, relative path or not.
    assert!(!dir.join(".git/hooks/h").exists());
    let _ = std::fs::remove_dir_all(dir);
}
