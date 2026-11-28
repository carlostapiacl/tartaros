//! tartaros as goose's `GOOSE_SANDBOX_COMMAND` (see "Use with goose" in the
//! README): the argv goose builds from the documented config, with `{cwd}` and
//! `{readonly:--write-deny}` expanded, runs the shell confined, and the status
//! command reports `confinement.active` for the same policy.

use std::path::{Path, PathBuf};
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_tartaros");

fn confinable() -> bool {
    if cfg!(target_os = "linux") {
        return std::fs::read_to_string("/sys/kernel/security/lsm").map(|s| s.contains("landlock")).unwrap_or(false);
    }
    cfg!(target_os = "macos")
}

/// The launcher argv after goose's expansion: `[tartaros, run, --write, {cwd},
/// {readonly:--write-deny}, --]`, then the shell goose starts.
fn launcher(cwd: &Path, readonly: &[PathBuf], tail: &[&str]) -> Vec<String> {
    let mut argv = vec!["run".to_string(), "--write".into(), cwd.display().to_string()];
    for p in readonly {
        argv.push("--write-deny".into());
        argv.push(p.display().to_string());
    }
    argv.push("--".into());
    argv.extend(tail.iter().map(|s| s.to_string()));
    argv
}

#[test]
fn goose_launcher_argv_confines_the_shell_and_reports_active() {
    if !confinable() {
        eprintln!("skip: no confinement backend here");
        return;
    }
    let base = std::env::temp_dir().join(format!("tartaros-goose-launcher-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let work = base.join("work");
    let goose_config = base.join("goose-config");
    std::fs::create_dir_all(work.join(".git/hooks")).unwrap();
    std::fs::create_dir_all(&goose_config).unwrap();
    let work = work.canonicalize().unwrap();
    let goose_config = goose_config.canonicalize().unwrap();
    let readonly = vec![goose_config.clone(), work.join(".git/hooks")];

    let mut status = vec!["explain".to_string(), "--json".into(), "--write".into(), work.display().to_string()];
    for p in &readonly {
        status.push("--write-deny".into());
        status.push(p.display().to_string());
    }
    let out = Command::new(BIN).args(&status).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("explain --json");
    assert_eq!(v["confinement"]["active"], true, "{}", String::from_utf8_lossy(&out.stdout));

    let script = format!(
        "echo ok > inside.txt; echo x > .git/hooks/pre-commit; echo x > {}/config.yaml; echo reached",
        goose_config.display()
    );
    let out = Command::new(BIN).current_dir(&work).args(launcher(&work, &readonly, &["sh", "-c", &script])).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("reached"), "the shell did not run: {}", String::from_utf8_lossy(&out.stderr));
    assert!(work.join("inside.txt").exists(), "the working directory is not writable");
    assert!(!work.join(".git/hooks/pre-commit").exists(), "a git hook was planted");
    assert!(!goose_config.join("config.yaml").exists(), "goose's config was written");
    let _ = std::fs::remove_dir_all(&base);
}
