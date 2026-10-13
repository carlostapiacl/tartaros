//! P1-B (process supervision) + P1-A (safe materialization) live checks (Linux).
//! `cargo run -p tartaros-linux --example p1b_lifecycle`

use tartaros_core::{Backend, Network, Policy};
use tartaros_linux::LandlockBackend;
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn main() {
    let be = LandlockBackend;
    let work = std::env::temp_dir().join(format!("sbx-life-{}", std::process::id()));
    std::fs::create_dir_all(work.join("src")).unwrap();
    let pass = |b: bool| if b { "PASS" } else { "FAIL" };

    // 1. timeout kills the process group (exit 124, ~2s not 30s)
    let p = Policy {
        role: "qa".into(),
        writable_roots: vec![work.clone()],
        network: Some(Network::Denied),
        timeout: Some(Duration::from_secs(2)),
        ..Default::default()
    };
    let t0 = Instant::now();
    let rc = be.run(&p, &["/bin/sh".into(), "-c".into(), "sleep 30".into()]).map(|o| o.exit_code).unwrap_or(-1);
    let elapsed = t0.elapsed().as_secs();
    println!("1. timeout:            rc={rc} elapsed={elapsed}s  {}", pass(rc == 124 && elapsed < 6));

    // 2. descendant cleanup: a backgrounded grandchild must not survive the run
    let pidfile = work.join("src/gpid");
    let p2 = Policy { timeout: Some(Duration::from_secs(2)), ..p.clone() };
    be.run(&p2, &["/bin/sh".into(), "-c".into(),
        format!("sleep 60 & echo $! > {}; sleep 30", pidfile.display())]).ok();
    let gpid = std::fs::read_to_string(&pidfile).unwrap_or_default().trim().parse::<i32>().unwrap_or(-1);
    let alive = gpid > 0 && unsafe { libc::kill(gpid, 0) } == 0;
    println!("2. descendant reaped:  gpid={gpid} alive={alive}  {}", pass(!alive));

    // 3. memory limit: allocating past the cap fails
    let p3 = Policy {
        role: "qa".into(),
        writable_roots: vec![work.clone()],
        network: Some(Network::Denied),
        max_memory_bytes: Some(256 * 1024 * 1024),
        ..Default::default()
    };
    let rc = be.run(&p3, &["/bin/sh".into(), "-c".into(),
        "python3 -c 'b=bytearray(600*1024*1024)' 2>/dev/null".into()]).map(|o| o.exit_code).unwrap_or(-1);
    println!("3. memory limit:       rc={rc}  {}", pass(rc != 0));

    // 4. P1-A: materialize refuses a symlinked ancestor
    let _ = std::fs::remove_dir_all(work.join(".claude"));
    #[cfg(unix)]
    std::os::unix::fs::symlink("/tmp", work.join(".claude")).ok();
    let p4 = Policy {
        role: "qa".into(),
        writable_roots: vec![work.clone()],
        materialize_absent_handoff: true,
        ..Default::default()
    };
    let res = be.run(&p4, &["/bin/true".into()]);
    println!("4. materialize vs symlink: {}  {}",
        if res.is_err() { "rechazado (fail-closed)" } else { "CORRIÓ" }, pass(res.is_err()));

    // control: resource-limited run of a normal command still works
    let _ = std::fs::remove_file(work.join(".claude"));
    let rc = be.run(&p3, &["/bin/sh".into(), "-c".into(), "echo ok > src/f.txt".into()]).map(|o| o.exit_code).unwrap_or(-1);
    println!("5. control write:      rc={rc}  {}", pass(rc == 0));

    std::fs::remove_dir_all(&work).ok();
    let _ = PathBuf::new();
}
