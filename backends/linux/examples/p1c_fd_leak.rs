//! Inherited-fd leak check (Linux) — the F-2 falsification harness. The parent
//! opens non-CLOEXEC fds (read, write, and a directory) to targets OUTSIDE the
//! territory; the confined child must not be able to use ANY of them (the backend
//! closes inherited fds before exec). A path-based sandbox that forgot this would
//! let a pre-opened capability bypass Landlock entirely.
//! Exits non-zero on any leak, so it doubles as a regression gate.
//! cargo run -p tartaros-linux --example p1c_fd_leak

use tartaros_core::{Backend, Network, Policy};
use tartaros_linux::LandlockBackend;
use std::ffi::CString;

/// Open `path` and clear CLOEXEC, so without the backend's fd-close it WOULD be
/// inherited by the child. Returns the raw fd.
fn leak_fd(path: &str, flags: i32) -> i32 {
    let cpath = CString::new(path).unwrap();
    let fd = unsafe { libc::open(cpath.as_ptr(), flags) };
    assert!(fd >= 0, "open {path} failed");
    unsafe {
        let f = libc::fcntl(fd, libc::F_GETFD);
        libc::fcntl(fd, libc::F_SETFD, f & !libc::FD_CLOEXEC);
    }
    fd
}

fn main() {
    let dir = std::env::temp_dir().join(format!("sbx-fd-{}", std::process::id()));
    let work = dir.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let secret = dir.join("secret.txt");
    std::fs::write(&secret, "TOPSECRET").unwrap();
    let out = dir.join("outside.txt");
    std::fs::write(&out, "original").unwrap();

    // Three inherited capabilities to OUTSIDE the territory: a read fd, a write fd,
    // and a directory fd (for an openat/procfs reopen).
    let rfd = leak_fd(secret.to_str().unwrap(), libc::O_RDONLY);
    let wfd = leak_fd(out.to_str().unwrap(), libc::O_WRONLY);
    let dfd = leak_fd(dir.to_str().unwrap(), libc::O_RDONLY | libc::O_DIRECTORY);

    let policy = Policy {
        role: "qa".into(),
        writable_roots: vec![work.clone()],
        network: Some(Network::Denied),
        ..Default::default()
    };
    let be = LandlockBackend;
    let sh = |script: String| {
        be.run(&policy, &["/bin/sh".into(), "-c".into(), script]).map(|o| o.exit_code).unwrap_or(-1)
    };

    // Each probe must FAIL (non-zero) — the fd was closed before the agent ran.
    let read_rc = sh(format!("cat <&{rfd}"));
    let procread_rc = sh(format!("head -c 100 /proc/self/fd/{rfd}"));
    let write_rc = sh(format!("echo pwned >&{wfd}"));
    let procwrite_rc = sh(format!("echo pwned > /proc/self/fd/{wfd}"));
    let dir_rc = sh(format!("cat /proc/self/fd/{dfd}/secret.txt"));

    unsafe {
        libc::close(rfd);
        libc::close(wfd);
        libc::close(dfd);
    }
    // Did the write actually land on the outside file (hard evidence of a leak)?
    let out_after = std::fs::read_to_string(&out).unwrap_or_default();
    std::fs::remove_dir_all(&dir).ok();

    let probes = [
        ("read via <&fd", read_rc),
        ("read via /proc/self/fd", procread_rc),
        ("write via >&fd", write_rc),
        ("write via /proc/self/fd", procwrite_rc),
        ("dir-fd reopen via /proc/self/fd", dir_rc),
    ];
    let mut leaked = out_after != "original"; // the file must be untouched
    for (name, rc) in probes {
        let ok = rc != 0;
        println!("  {name}: rc={rc}  {}", if ok { "PASS (closed)" } else { "FAIL (leak)" });
        if !ok {
            leaked = true;
        }
    }
    if out_after != "original" {
        println!("  outside file was MODIFIED through the inherited write fd — LEAK");
    }
    if leaked {
        eprintln!("FAIL: an inherited fd survived into the confined agent");
        std::process::exit(1);
    }
    println!("PASS: every inherited fd (read/write/dir) was revoked before exec");
}
