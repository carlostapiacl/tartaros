//! Live check of Landlock per-port network enforcement (Linux). Needs python3
//! and curl. Run on a kernel >= 6.7: `cargo run -p tartaros-linux --example netcheck`.
//!
//! Policy grants loopback port 8001 only. Expect: connect to 8001 works, 8787 is
//! blocked (port not granted), and an external host is blocked.

use tartaros_core::{Backend, Network, Policy};
use tartaros_linux::LandlockBackend;
use std::process::{Child, Command};
use std::thread::sleep;
use std::time::Duration;

fn serve(port: u16) -> Child {
    Command::new("python3")
        .args(["-m", "http.server", &port.to_string(), "--bind", "127.0.0.1"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("python3 http.server")
}

fn main() {
    let be = LandlockBackend;
    let work = std::env::temp_dir().join(format!("sbx-net-{}", std::process::id()));
    std::fs::create_dir_all(&work).unwrap();

    let mut s1 = serve(8001);
    let mut s2 = serve(8787);
    sleep(Duration::from_millis(800));

    let policy = Policy {
        role: "qa".into(),
        writable_roots: vec![work.clone()],
        network: Some(Network::Denied),
        local_ports: vec![8001],
        ..Default::default()
    };

    let curl = |url: &str| -> i32 {
        be.run(
            &policy,
            &[
                "curl".into(), "-s".into(), "-o".into(), "/dev/null".into(),
                "--max-time".into(), "4".into(), url.into(),
            ],
        )
        .map(|o| o.exit_code)
        .unwrap_or(-1)
    };

    let pass = |b: bool| if b { "PASS" } else { "FAIL" };

    println!("backend: {}", be.name());
    let rc = curl("http://127.0.0.1:8001/");
    println!("granted port 8001:      rc={rc}  {}", pass(rc == 0));
    let rc = curl("http://127.0.0.1:8787/");
    println!("ungranted port 8787:    rc={rc}  {}", pass(rc != 0));
    let rc = curl("http://1.1.1.1/");
    println!("external host:          rc={rc}  {}", pass(rc != 0));

    let _ = s1.kill();
    let _ = s2.kill();
    let _ = std::fs::remove_dir_all(&work);
}
