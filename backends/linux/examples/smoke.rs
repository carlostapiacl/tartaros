//! Live smoke of the Linux (Landlock) backend. Run on a Landlock-capable
//! kernel: `cargo run -p seisin-sandbox-linux --example smoke`.
//!
//! Proves the seisin Linux edge: a deny-inside-allow policy (which nono refuses)
//! is enforced — writes land in safe subtrees, a nested `.git/hooks` is not
//! writable, and renaming its ancestor is denied.

use seisin_sandbox_core::{Backend, Network, Policy};
use seisin_sandbox_linux::LandlockBackend;
use std::fs;
use std::process::Command;

fn main() {
    let be = LandlockBackend;
    let work = std::env::temp_dir().join(format!("sbx-lx-{}", std::process::id()));
    let nested = work.join("a").join("nested");
    fs::create_dir_all(work.join("src")).unwrap();
    fs::create_dir_all(nested.join(".git/hooks")).unwrap();
    fs::create_dir_all(nested.join(".git/objects")).unwrap();
    run_plain(&["git", "-C", nested.to_str().unwrap(), "init", "-q"]);

    let policy = Policy {
        writable_roots: vec![work.clone()],
        network: Some(Network::Denied),
        isolate_process_info: true,
        ..Default::default()
    };

    let sh = |script: String| -> i32 {
        match be.run(&policy, &["/bin/sh".into(), "-c".into(), script]) {
            Ok(o) => o.exit_code,
            Err(e) => { eprintln!("run error: {}", e.reason); -1 }
        }
    };

    println!("backend: {}", be.name());

    // 1. control: write in a safe subtree
    let ok = work.join("src/ok.txt");
    let rc = sh(format!("echo x > {}", ok.display()));
    println!("1. write in safe subtree:        rc={rc} exists={}  {}", ok.exists(), pass(rc == 0 && ok.exists()));

    // 2. write outside the workspace
    let outside = work.parent().unwrap().join(format!("sbx-lx-out-{}", std::process::id()));
    let rc = sh(format!("echo x > {}", outside.display()));
    println!("2. write outside workspace:      rc={rc} exists={}  {}", outside.exists(), pass(rc != 0 && !outside.exists()));
    let _ = fs::remove_file(&outside);

    // 3. nested .git/hooks (deny-inside-allow — nono can't even express this)
    let hook = nested.join(".git/hooks/pre-commit");
    let _ = fs::remove_file(&hook);
    let rc = sh(format!("echo x > {}", hook.display()));
    println!("3. nested .git/hooks write:      rc={rc} exists={}  {}", hook.exists(), pass(!hook.exists()));

    // 3b. but git's own objects dir stays writable (carve keeps it)
    let obj = nested.join(".git/objects/probe");
    let _ = fs::remove_file(&obj);
    let rc = sh(format!("echo x > {}", obj.display()));
    println!("3b .git/objects still writable:  rc={rc} exists={}  {}", obj.exists(), pass(rc == 0 && obj.exists()));

    // 4. ancestor rename is denied (can't relocate the protected path)
    let rc = sh(format!("cd {} && mv a/nested a/n2", work.display()));
    let renamed = work.join("a/n2").exists();
    println!("4. rename ancestor of .git:      rc={rc} renamed={}  {}", renamed, pass(!renamed));
    if renamed { let _ = fs::rename(work.join("a/n2"), &nested); }

    // 5. exit status on signal death
    let rc = sh("kill -TERM $$".into());
    println!("5. exit on SIGTERM:              rc={rc} (want 143)  {}", pass(rc == 143));

    let _ = fs::remove_dir_all(&work);
}

fn pass(b: bool) -> &'static str { if b { "PASS" } else { "FAIL" } }
fn run_plain(args: &[&str]) { let _ = Command::new(args[0]).args(&args[1..]).status(); }
