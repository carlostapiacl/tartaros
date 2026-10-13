//! Measure a portable mitigation for P1-3 (cross-process env read) WITHOUT a PID
//! namespace: exclude /proc from the read grant via read_denies. Uses a real
//! victim process holding a secret, and checks tool impact (incl. /proc/self).
//! `cargo run -p tartaros-linux --example p1_proc_isolation`

use tartaros_core::{Backend, Network, Policy};
use tartaros_linux::LandlockBackend;
use std::path::PathBuf;
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

fn main() {
    let work = std::env::temp_dir().join(format!("sbx-p1proc-{}", std::process::id()));
    std::fs::create_dir_all(&work).unwrap();
    let be = LandlockBackend;

    // victim: holds a secret in its environment, outside the sandbox
    let mut victim = Command::new("sleep")
        .arg("30")
        .env("VICTIM_SECRET", "s3cr3t-in-env")
        .spawn()
        .unwrap();
    let vpid = victim.id();
    sleep(Duration::from_millis(200));

    for (label, read_denies) in [
        ("sin mitigación", vec![]),
        ("/proc en read_denies", vec![PathBuf::from("/proc")]),
    ] {
        let policy = Policy {
            role: "qa".into(),
            writable_roots: vec![work.clone()],
            network: Some(Network::Denied),
            read_denies,
            ..Default::default()
        };
        let out = work.join("env");
        be.run(&policy, &["/bin/sh".into(), "-c".into(),
            format!("cat /proc/{vpid}/environ > {} 2>/dev/null", out.display())]).ok();
        let got = std::fs::read(&out).unwrap_or_default();
        let leaked = got.windows(13).any(|w| w == b"s3cr3t-in-env");
        let _ = std::fs::remove_file(&out);

        let rc = |s: String| be.run(&policy, &["/bin/sh".into(), "-c".into(), s]).map(|o| o.exit_code).unwrap_or(-1);
        println!("=== {label} ===");
        println!("  environ víctima legible: {}  ({})", leaked, if leaked { "FUGA" } else { "bloqueado" });
        println!("  sh / cat / ls / curl / git / python3: {} {} {} {} {} {}",
            rc("echo ok>/dev/null".into()),
            rc("cat /etc/hostname>/dev/null 2>&1".into()),
            rc("ls /usr/bin>/dev/null 2>&1".into()),
            rc("curl --version>/dev/null 2>&1".into()),
            rc("git --version>/dev/null 2>&1".into()),
            rc("python3 -c 'import os;os.getpid()'>/dev/null 2>&1".into()));
        println!("  /proc/self/status: rc={}   /proc/self/maps(python): ver arriba", rc("cat /proc/self/status>/dev/null 2>&1".into()));
    }

    let _ = victim.kill();
    std::fs::remove_dir_all(&work).ok();
}
