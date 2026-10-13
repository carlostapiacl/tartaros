//! Adversarial repro (external review P0): a `read_denies` path INSIDE a
//! writable root. If the write rule (`all`, which includes read) re-opens read,
//! the secret is readable despite read_denies — a policy contradiction.
//! `cargo run -p seisin-sandbox-linux --example p0_readdeny_in_writable`

use seisin_sandbox_core::{Backend, Network, Policy};
use seisin_sandbox_linux::LandlockBackend;

fn main() {
    let work = std::env::temp_dir().join(format!("sbx-p0-{}", std::process::id()));
    let vault = work.join("vault");
    std::fs::create_dir_all(&vault).unwrap();
    std::fs::write(vault.join("key"), "TOP-SECRET").unwrap();

    let policy = Policy {
        role: "qa".into(),
        writable_roots: vec![work.clone()],       // vault is INSIDE this
        read_denies: vec![vault.clone()],          // but declared read-denied
        network: Some(Network::Denied),
        ..Default::default()
    };
    let be = LandlockBackend;
    let sh = |s: String| be.run(&policy, &["/bin/sh".into(), "-c".into(), s]).map(|o| o.exit_code).unwrap_or(-1);

    println!("backend: {}", be.name());
    let rc = sh(format!("cat {}/key >/dev/null 2>&1", vault.display()));
    if rc == 0 {
        println!("read vault/key: rc={rc}  *** BUG CONFIRMED: secret readable inside writable root ***");
    } else {
        println!("read vault/key: rc={rc}  OK: secret not readable (policy holds)");
    }
    // control: can still write elsewhere in work
    let rc2 = sh(format!("echo x > {}/ok.txt", work.display()));
    println!("write work/ok.txt: rc={rc2}  (expect 0)");

    std::fs::remove_dir_all(&work).ok();
}
