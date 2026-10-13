//! Inherited-fd leak check (Linux). The parent opens a non-CLOEXEC fd to a secret
//! OUTSIDE the territory; the confined child must not be able to read through it
//! (the backend closes inherited fds before exec).
//! cargo run -p tartaros-linux --example p1c_fd_leak

use tartaros_core::{Backend, Network, Policy};
use tartaros_linux::LandlockBackend;
use std::ffi::CString;

fn main() {
    let dir = std::env::temp_dir().join(format!("sbx-fd-{}", std::process::id()));
    let work = dir.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let secret = dir.join("secret.txt");
    std::fs::write(&secret, "TOPSECRET").unwrap();

    // open a NON-CLOEXEC fd to the secret (std File is CLOEXEC, so use raw open)
    let cpath = CString::new(secret.to_string_lossy().as_bytes()).unwrap();
    let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY) };
    assert!(fd >= 0, "open failed");
    // clear CLOEXEC so it would be inherited without the backend's fd-close
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
    }

    let policy = Policy {
        role: "qa".into(),
        writable_roots: vec![work.clone()],
        network: Some(Network::Denied),
        ..Default::default()
    };
    let be = LandlockBackend;
    // child tries to read from the inherited fd number
    let rc = be.run(&policy, &["/bin/sh".into(), "-c".into(),
        format!("cat <&{fd} 2>/dev/null")]).map(|o| o.exit_code).unwrap_or(-1);
    let got = be.run(&policy, &["/bin/sh".into(), "-c".into(),
        format!("head -c 100 /proc/self/fd/{fd} 2>/dev/null")]).map(|o| o.exit_code).unwrap_or(-1);
    println!("read via inherited fd {fd}: rc={rc} / proc-fd rc={got}  {}",
        if rc != 0 { "PASS (fd closed)" } else { "FAIL (leak)" });

    unsafe { libc::close(fd); }
    std::fs::remove_dir_all(&dir).ok();
}
