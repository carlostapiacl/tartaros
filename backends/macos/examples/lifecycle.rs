use tartaros_core::{Backend, Network, Policy};
use tartaros_macos::SeatbeltBackend;
use std::time::{Duration, Instant};
fn main() {
    let work = std::env::temp_dir().join(format!("sbx-mlife-{}", std::process::id()));
    std::fs::create_dir_all(&work).unwrap();
    let p = Policy { role: "qa".into(), writable_roots: vec![work.clone()], network: Some(Network::Denied), timeout: Some(Duration::from_secs(2)), ..Default::default() };
    let be = SeatbeltBackend;
    let t0 = Instant::now();
    let rc = be.run(&p, &["/bin/sh".into(), "-c".into(), "sleep 30".into()]).map(|o| o.exit_code).unwrap_or(-1);
    let el = t0.elapsed().as_secs();
    println!("timeout: rc={rc} elapsed={el}s  {}", if rc == 124 && el < 6 { "PASS" } else { "FAIL" });
    std::fs::remove_dir_all(&work).ok();
}
