//! `run --snapshot` and `tartaros rollback`: the roots come back as they were,
//! a directory the agent swapped for a link out of the root is not written
//! through, read-denied and excluded paths are left alone, and the rollback can
//! itself be undone.
#![cfg(unix)]

use std::fs;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_tartaros");

fn id_from(stderr: &str, marker: &str) -> String {
    let at = stderr.find(marker).unwrap_or_else(|| panic!("no {marker:?} in {stderr}")) + marker.len();
    stderr[at..].split_whitespace().next().unwrap().trim_end_matches(';').to_string()
}

#[test]
fn rollback_restores_the_roots_and_never_writes_outside() {
    let base = std::env::temp_dir().join(format!("tartaros-snap-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    let (work, outside, state) = (base.join("work"), base.join("outside"), base.join("state"));
    fs::create_dir_all(work.join("src/lib")).unwrap();
    fs::create_dir_all(work.join("node_modules/pkg")).unwrap();
    fs::create_dir_all(work.join("secret")).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(work.join("src/a.txt"), "original").unwrap();
    fs::write(work.join("src/lib/b.txt"), "keep me").unwrap();
    fs::write(work.join("node_modules/pkg/i.js"), "dep").unwrap();
    fs::write(work.join("secret/token"), "s3cr3t").unwrap();
    let w = work.display().to_string();
    let script = format!(
        "echo changed > {w}/src/a.txt; rm {w}/src/lib/b.txt; echo new > {w}/src/new.txt; \
         rm -r {w}/src/lib && ln -s {o} {w}/src/lib; echo built > {w}/node_modules/pkg/i.js; \
         cat {s}/snapshots/*.json >/dev/null 2>&1 && echo LEAK",
        o = outside.display(),
        s = state.display()
    );
    let out = Command::new(BIN)
        .env("TARTAROS_STATE_DIR", &state)
        .args(["run", "--snapshot", "--snapshot-exclude", "node_modules", "--write", &w, "--read-deny", &format!("{w}/secret"), "--"])
        .args(["sh", "-c", &script])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!String::from_utf8_lossy(&out.stdout).contains("LEAK"), "the agent read the snapshot store");
    let id = id_from(&err, "snapshot ");
    assert!(err.contains("1 added"), "{err}");
    assert!(fs::symlink_metadata(work.join("src/lib")).unwrap().file_type().is_symlink());

    let rb = Command::new(BIN).env("TARTAROS_STATE_DIR", &state).args(["rollback", &id]).output().unwrap();
    let rb_err = String::from_utf8_lossy(&rb.stderr);
    assert!(rb.status.success(), "{rb_err}");
    assert_eq!(fs::read_to_string(work.join("src/a.txt")).unwrap(), "original");
    assert!(fs::symlink_metadata(work.join("src/lib")).unwrap().is_dir(), "the link was not replaced by the directory");
    assert_eq!(fs::read_to_string(work.join("src/lib/b.txt")).unwrap(), "keep me");
    assert!(!work.join("src/new.txt").exists());
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 0, "rollback wrote through the link");
    // Excluded and read-denied: left as they are.
    assert_eq!(fs::read_to_string(work.join("node_modules/pkg/i.js")).unwrap(), "built\n");
    assert_eq!(fs::read_to_string(work.join("secret/token")).unwrap(), "s3cr3t");
    let snaps = fs::read_dir(state.join("snapshots/objects")).unwrap().flatten().flat_map(|d| fs::read_dir(d.path()).unwrap().flatten());
    for o in snaps {
        assert_ne!(fs::read_to_string(o.path()).unwrap_or_default(), "s3cr3t", "a read-denied file was copied into the store");
    }

    // The rollback can be undone.
    let before = id_from(&rb_err, "the state it replaced is snapshot ");
    let undo = Command::new(BIN).env("TARTAROS_STATE_DIR", &state).args(["rollback", &before]).output().unwrap();
    assert!(undo.status.success(), "{}", String::from_utf8_lossy(&undo.stderr));
    assert_eq!(fs::read_to_string(work.join("src/a.txt")).unwrap(), "changed\n");
    assert!(work.join("src/new.txt").exists());

    // A store inside a writable root is refused.
    let inside = Command::new(BIN)
        .env("TARTAROS_STATE_DIR", work.join(".state"))
        .args(["run", "--snapshot", "--write", &w, "--", "true"])
        .output()
        .unwrap();
    assert_eq!(inside.status.code(), Some(78), "{}", String::from_utf8_lossy(&inside.stderr));
    let _ = fs::remove_dir_all(base);
}
