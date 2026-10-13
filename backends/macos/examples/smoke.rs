//! Live smoke test of the macOS backend against the trust-handoff checks —
//! the ones where Codex/nono/srt were measured to fail (nested .git, ancestor
//! rename). Run: `cargo run -p seisin-sandbox-macos --example smoke`
//!
//! Touches only a fresh temp dir and one marker file; cleans up on exit.

use seisin_sandbox_core::{Backend, Network, Policy};
use seisin_sandbox_macos::SeatbeltBackend;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let be = SeatbeltBackend;
    let work = std::env::temp_dir().join(format!("sbx-smoke-{}", std::process::id()));
    let nested = work.join("a").join("nested");
    fs::create_dir_all(work.join(".git/hooks")).unwrap();
    fs::create_dir_all(nested.join(".git/hooks")).unwrap();
    // make nested a real repo so a commit would fire its hook
    run_plain(&["git", "-C", nested.to_str().unwrap(), "init", "-q"]);
    run_plain(&["git", "-C", nested.to_str().unwrap(), "config", "user.email", "a@b.c"]);
    run_plain(&["git", "-C", nested.to_str().unwrap(), "config", "user.name", "a"]);
    fs::write(nested.join("f"), "x").unwrap();
    run_plain(&["git", "-C", nested.to_str().unwrap(), "add", "f"]);

    let policy = Policy {
        writable_roots: vec![work.clone()],
        network: Some(Network::Denied),
        isolate_process_info: true,
        ..Default::default()
    };

    let sh = |script: String| -> i32 {
        be.run(&policy, &["/bin/sh".into(), "-c".into(), script]).unwrap().exit_code
    };

    println!("backend: {}", be.name());

    // 1. control
    let c = work.join("ok.txt");
    let rc = sh(format!("echo x > {}", c.display()));
    println!("1a. write in WORK:                 rc={rc} exists={}  {}", c.exists(), ok(rc == 0 && c.exists()));
    let outside = work.parent().unwrap().join(format!("sbx-outside-{}", std::process::id()));
    let rc = sh(format!("echo x > {}", outside.display()));
    println!("1b. write outside WORK:            rc={rc} exists={}  {}", outside.exists(), ok(rc != 0 && !outside.exists()));
    let _ = fs::remove_file(&outside);

    // 2. nested .git/hooks — direct write (Codex: allowed; us: must deny)
    let hook = nested.join(".git/hooks/pre-commit");
    let _ = fs::remove_file(&hook);
    let rc = sh(format!("echo x > {}", hook.display()));
    println!("2.  nested .git/hooks direct:      rc={rc} exists={}  {}", hook.exists(), ok(!hook.exists()));

    // 3. ancestor-rename maneuver + does the planted hook run outside?
    let marker = work.parent().unwrap().join(format!("sbx-marker-{}", std::process::id()));
    let _ = fs::remove_file(&marker);
    let maneuver = format!(
        "cd {w} && mv a/nested a/n2 && printf '#!/bin/sh\\ntouch {m}\\n' > a/n2/.git/hooks/pre-commit && chmod +x a/n2/.git/hooks/pre-commit && mv a/n2 a/nested",
        w = work.display(), m = marker.display()
    );
    let rc = sh(maneuver);
    // whatever happened inside, restore the dir name for the commit test
    if work.join("a/n2").exists() { let _ = fs::rename(work.join("a/n2"), &nested); }
    run_plain(&["git", "-C", nested.to_str().unwrap(), "commit", "-q", "-m", "x"]);
    let leaked = marker.exists();
    println!("3.  ancestor-rename maneuver:      rc={rc}");
    println!("    planted hook ran OUTSIDE box:  {}  {}", leaked, ok(!leaked));
    let _ = fs::remove_file(&marker);
    let _ = fs::remove_file(&hook);

    // 4. lifecycle: exit status on signal death
    let rc = sh("kill -TERM $$".into());
    println!("4.  exit on SIGTERM:               rc={rc} (want 143)  {}", ok(rc == 143));

    let _ = fs::remove_dir_all(&work);
}

fn ok(b: bool) -> &'static str { if b { "PASS" } else { "FAIL" } }

fn run_plain(args: &[&str]) {
    let _ = Command::new(args[0]).args(&args[1..]).status();
}

#[allow(dead_code)]
fn _unused(_: PathBuf) {}
