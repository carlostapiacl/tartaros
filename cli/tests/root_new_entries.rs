//! `explain --settings` warns about a writable root exactly when `run` under the
//! same settings cannot create a new entry directly in it (Linux).
//!
//! Without a mount namespace the Landlock carve never grants a directory that
//! has a write deny below it, only its existing children. Measured on
//! ubuntu-latest (AppArmor restricting unprivileged user namespaces): a consumer
//! read `explain` exiting 0 as "this will hold", and its first write into the
//! root of an allowWrite (`/tmp`, with a deny on `/tmp/claude`) was refused.
//! The warning is the one thing that tells it beforehand, so this drives the
//! real binary against the real kernel and checks that the two agree, on
//! whichever host it runs: with namespaces the bind mounts lift the limit and
//! there must be no warning; without them there must be one.
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_tartaros");

fn landlock() -> bool {
    std::fs::read_to_string("/sys/kernel/security/lsm").map(|s| s.contains("landlock")).unwrap_or(false)
}

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("tartaros-rootnew-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d.canonicalize().unwrap()
}

fn settings(dir: &Path, root: &Path, denies: &[PathBuf]) -> PathBuf {
    let list: Vec<String> = denies.iter().map(|d| format!("{:?}", d.display().to_string())).collect();
    let f = dir.join("settings.json");
    std::fs::write(
        &f,
        format!(
            r#"{{"filesystem":{{"allowWrite":[{:?}],"denyWrite":[{}]}},"network":{{"allowedDomains":[]}}}}"#,
            root.display().to_string(),
            list.join(",")
        ),
    )
    .unwrap();
    f
}

/// (explain warned about `root`, run created a new entry in `root`)
fn measure(tag: &str, denies: impl Fn(&Path) -> Vec<PathBuf>) -> (bool, bool) {
    let dir = scratch(tag);
    let root = dir.join("root");
    std::fs::create_dir_all(root.join("claude")).unwrap();
    let f = settings(&dir, &root, &denies(&root));
    let ex = Command::new(BIN).args(["explain", "--settings"]).arg(&f).output().unwrap();
    assert_eq!(ex.status.code(), Some(0), "explain: {}", String::from_utf8_lossy(&ex.stderr));
    let out = String::from_utf8_lossy(&ex.stdout);
    let warned = out
        .lines()
        .any(|l| l.starts_with("warning:") && l.contains(&format!("created directly in {} ", root.display())));
    let new = root.join(".new-entry");
    let run = Command::new(BIN)
        .args(["run", "--settings"])
        .arg(&f)
        .args(["--", "/bin/sh", "-c"])
        .arg(format!("echo IN > '{}' 2>/dev/null; true", new.display()))
        .output()
        .unwrap();
    assert_eq!(run.status.code(), Some(0), "run: {}", String::from_utf8_lossy(&run.stderr));
    (warned, new.exists())
}

#[test]
fn the_warning_is_said_exactly_when_the_run_cannot_create_at_the_root() {
    if !landlock() {
        eprintln!("skipped: no Landlock on this kernel");
        return;
    }
    let cases: Vec<(&str, Box<dyn Fn(&Path) -> Vec<PathBuf>>)> = vec![
        ("none", Box::new(|_| vec![])),
        ("existing", Box::new(|r| vec![r.join("claude")])),
        ("absent-inside", Box::new(|r| vec![r.join("not-yet")])),
        ("existing+absent-inside", Box::new(|r| vec![r.join("claude"), r.join("not-yet")])),
        ("existing+absent-outside", Box::new(|r| vec![r.join("claude"), r.parent().unwrap().join("elsewhere/not-yet")])),
    ];
    for (tag, denies) in cases {
        let (warned, created) = measure(tag, denies);
        eprintln!("{tag}: warned={warned} created={created}");
        assert_ne!(warned, created, "{tag}: explain warned={warned}, but the run created={created}");
    }
}

#[test]
fn an_absent_deny_inside_the_root_always_costs_new_entries_there() {
    if !landlock() {
        eprintln!("skipped: no Landlock on this kernel");
        return;
    }
    // On every host: a bind mount cannot cover a path that is not there.
    let (warned, created) = measure("absent-always", |r| vec![r.join("not-yet")]);
    assert!(warned && !created, "warned={warned} created={created}");
}
