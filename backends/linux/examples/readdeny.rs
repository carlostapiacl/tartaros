//! Live check of secret read-deny (Linux/Landlock). The agent may read the rest
//! of the filesystem but NOT the denied secret dir.
//! `cargo run -p tartaros-linux --example readdeny`

use tartaros_core::{Backend, Network, Policy};
use tartaros_linux::LandlockBackend;
use std::path::PathBuf;

fn main() {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let ssh = format!("{home}/.ssh");
    std::fs::create_dir_all(&ssh).ok();
    std::fs::write(format!("{ssh}/id_demo"), "SECRET-KEY").unwrap();

    let work = std::env::temp_dir().join(format!("sbx-rd-{}", std::process::id()));
    std::fs::create_dir_all(&work).unwrap();

    let policy = Policy {
        role: "qa".into(),
        writable_roots: vec![work.clone()],
        network: Some(Network::Denied),
        read_denies: vec![PathBuf::from(&ssh)],
        ..Default::default()
    };
    let be = LandlockBackend;
    let sh = |s: String| be.run(&policy, &["/bin/sh".into(), "-c".into(), s]).map(|o| o.exit_code).unwrap_or(-1);
    let pass = |b: bool| if b { "PASS" } else { "FAIL" };

    println!("backend: {}", be.name());
    let rc = sh(format!("cat {ssh}/id_demo >/dev/null 2>&1"));
    println!("read secret ~/.ssh/id:   rc={rc}  {}", pass(rc != 0));
    let rc = sh("cat /etc/hostname >/dev/null 2>&1".into());
    println!("read /etc/hostname:      rc={rc}  {}", pass(rc == 0));
    let rc = sh("ls /usr/bin >/dev/null 2>&1".into());
    println!("list /usr/bin:           rc={rc}  {}", pass(rc == 0));

    std::fs::remove_dir_all(&work).ok();
    std::fs::remove_file(format!("{ssh}/id_demo")).ok();
}
