//! Integration test: our Seatbelt backend enforces the trust-handoff set live.
//! These are the checks Codex/nono/srt were measured to fail (2026-10-13).
//! macOS only (needs /usr/bin/sandbox-exec).
#![cfg(target_os = "macos")]

use tartaros_core::{Backend, Network, Policy};
use tartaros_macos::SeatbeltBackend;
use std::fs;

fn mk_work() -> std::path::PathBuf {
    // The clock on macOS has microsecond resolution: two tests on parallel threads
    // got the same directory, and one's cleanup removed the other's files. The
    // counter keeps each test's directory its own.
    static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let work = std::env::temp_dir().join(format!(
        "sbx-it-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    fs::create_dir_all(work.join(".git/hooks")).unwrap();
    let nested = work.join("a/nested");
    fs::create_dir_all(nested.join(".git/hooks")).unwrap();
    work
}

fn policy_for(work: &std::path::Path) -> Policy {
    Policy {
        writable_roots: vec![work.to_path_buf()],
        network: Some(Network::Denied),
        isolate_process_info: true,
        ..Default::default()
    }
}

fn sh(be: &SeatbeltBackend, policy: &Policy, script: &str) -> i32 {
    be.run(policy, &["/bin/sh".into(), "-c".into(), script.into()])
        .unwrap()
        .exit_code
}

#[test]
fn control_write_in_workspace_is_allowed() {
    let work = mk_work();
    let be = SeatbeltBackend;
    let p = policy_for(&work);
    let f = work.join("ok.txt");
    let rc = sh(&be, &p, &format!("echo x > {}", f.display()));
    assert_eq!(rc, 0);
    assert!(f.exists());
    fs::remove_dir_all(&work).ok();
}

#[test]
fn write_outside_workspace_is_denied() {
    let work = mk_work();
    let be = SeatbeltBackend;
    let p = policy_for(&work);
    let outside = std::env::temp_dir().join(format!("sbx-outside-{}", std::process::id()));
    let _ = fs::remove_file(&outside);
    let rc = sh(&be, &p, &format!("echo x > {}", outside.display()));
    assert_ne!(rc, 0);
    assert!(!outside.exists());
    fs::remove_dir_all(&work).ok();
}

#[test]
fn nested_git_hook_direct_write_is_denied() {
    let work = mk_work();
    let be = SeatbeltBackend;
    let p = policy_for(&work);
    let hook = work.join("a/nested/.git/hooks/pre-commit");
    let _ = fs::remove_file(&hook);
    let rc = sh(&be, &p, &format!("echo x > {}", hook.display()));
    assert_ne!(rc, 0, "writing a nested repo's hook must be denied");
    assert!(!hook.exists());
    fs::remove_dir_all(&work).ok();
}

#[test]
fn ancestor_rename_cannot_make_a_handoff_path_writable() {
    let work = mk_work();
    let be = SeatbeltBackend;
    let p = policy_for(&work);
    // Rename a benign ancestor of the protected .git out of the way, then try to
    // plant a hook at the relocated path. The protection is any-depth, so the
    // rename of an ordinary directory may succeed but the hook stays unwritable
    // wherever it lands under the root. The guarantee is "no writable handoff
    // path", not "no directory renames" — the move cannot escape the deny
    // because outside the root is not writable either.
    let rc = sh(
        &be,
        &p,
        &format!(
            "cd {} && mv a/nested a/n2 2>/dev/null; echo x > a/n2/.git/hooks/pre-commit",
            work.display()
        ),
    );
    assert_ne!(rc, 0, "a relocated .git/hooks must remain unwritable");
    assert!(
        !work.join("a/n2/.git/hooks/pre-commit").exists(),
        "no hook may be planted at the relocated path"
    );
    fs::remove_dir_all(&work).ok();
}

#[test]
fn secret_read_deny_blocks_only_the_secret() {
    let work = mk_work();
    let secret = work.join("vault");
    fs::create_dir_all(&secret).unwrap();
    fs::write(secret.join("key"), "topsecret").unwrap();
    let be = SeatbeltBackend;
    let mut p = policy_for(&work);
    p.read_denies = vec![secret.clone()];

    // reading the secret is denied
    let rc = be
        .run(&p, &["/bin/cat".into(), secret.join("key").to_string_lossy().into()])
        .unwrap()
        .exit_code;
    assert_ne!(rc, 0, "reading the secret dir must be denied");

    // reading elsewhere still works
    let rc = be
        .run(&p, &["/bin/cat".into(), "/etc/hosts".into()])
        .unwrap()
        .exit_code;
    assert_eq!(rc, 0, "reading a non-secret path must still work");

    fs::remove_dir_all(&work).ok();
}

#[test]
fn exit_status_reflects_signal_death() {
    let work = mk_work();
    let be = SeatbeltBackend;
    let p = policy_for(&work);
    let rc = sh(&be, &p, "kill -TERM $$");
    assert_eq!(rc, 143, "128 + SIGTERM(15)");
    fs::remove_dir_all(&work).ok();
}

// Ensures a real tool (git) actually runs under the profile, not just sh.
#[test]
fn git_runs_under_profile() {
    let work = mk_work();
    let be = SeatbeltBackend;
    let p = policy_for(&work);
    let rc = be
        .run(&p, &["git".into(), "--version".into()])
        .unwrap()
        .exit_code;
    assert_eq!(rc, 0, "git must run under the sandbox profile");
    fs::remove_dir_all(&work).ok();
}

// --max-mem is an address-space cap (RLIMIT_AS) that the Darwin kernel does not
// enforce (setrlimit returns EINVAL). It must be REFUSED up front with a clear
// message, not crash the run with a cryptic "spawning sandbox-exec: Invalid
// argument". The caps that DO work on macOS (--max-procs, --max-cpu) must still
// be accepted.
#[test]
fn max_mem_is_refused_on_macos_with_a_clear_message() {
    let work = mk_work();
    let be = SeatbeltBackend;
    let mut p = policy_for(&work);
    p.max_memory_bytes = Some(512 * 1024 * 1024);
    let err = be.validate(&p).expect_err("--max-mem must be refused on macOS");
    assert!(err.reason.contains("--max-mem"), "message must name the flag: {}", err.reason);
    assert!(!err.reason.contains("Invalid argument"), "must be a clear refusal, not the raw errno");

    // the working caps are still accepted
    let mut ok = policy_for(&work);
    ok.max_processes = Some(256);
    ok.max_cpu_secs = Some(600);
    assert!(be.validate(&ok).is_ok(), "--max-procs/--max-cpu must still be accepted");
    fs::remove_dir_all(&work).ok();
}
