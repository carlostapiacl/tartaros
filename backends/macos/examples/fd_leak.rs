//! Inherited-fd leak check (macOS). Parent opens a non-CLOEXEC fd to a secret
//! outside the territory; the confined child must not read through it.
//! cargo run -p seisin-sandbox-macos --example fd_leak

use seisin_sandbox_core::{Backend, Network, Policy};
use seisin_sandbox_macos::SeatbeltBackend;
use std::ffi::CString;

fn main() {
    let dir = std::env::temp_dir().join(format!("sbx-fdm-{}", std::process::id()));
    let work = dir.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let secret = dir.join("secret.txt");
    std::fs::write(&secret, "TOPSECRET").unwrap();

    let cpath = CString::new(secret.to_string_lossy().as_bytes()).unwrap();
    let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY) };
    assert!(fd >= 0);
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
    let be = SeatbeltBackend;
    let rc = be.run(&policy, &["/bin/sh".into(), "-c".into(), format!("cat <&{fd} 2>/dev/null")])
        .map(|o| o.exit_code).unwrap_or(-1);
    println!("read via inherited fd {fd}: rc={rc}  {}", if rc != 0 { "PASS (fd closed)" } else { "FAIL (leak)" });
    unsafe { libc::close(fd); }
    std::fs::remove_dir_all(&dir).ok();
}
