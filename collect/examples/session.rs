//! A real observed session (Linux): spawn a confined agent and let the
//! collectors watch its process tree, producing the effect log — the first-hand
//! record that feeds the intent layer. Run on a Landlock kernel; needs curl.
//! `cargo run -p tartaros-collect --example session`

use tartaros_collect::{
    observe_until_exit, NetworkCollector, ProcessCollector, SecretCollector,
};
use tartaros_core::{Collector, FilterSink, JsonlSink, Network, Policy, RecordMode};
use tartaros_linux::LandlockBackend;
use std::io::Write;
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

fn main() {
    // a granted local service (within territory) the agent may reach
    let app = TcpListener::bind("127.0.0.1:0").unwrap();
    let app_port = app.local_addr().unwrap().port();
    thread::spawn(move || {
        for s in app.incoming().flatten() {
            let mut s = s;
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });

    // a secret on disk the agent will open (allowed read, but we SEE it)
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let ssh = format!("{home}/.ssh");
    std::fs::create_dir_all(&ssh).ok();
    std::fs::write(format!("{ssh}/id_demo"), "PRIVATE-KEY-MATERIAL").ok();

    let work = std::env::temp_dir().join(format!("sbx-sess-{}", std::process::id()));
    std::fs::create_dir_all(&work).unwrap();

    let policy = Policy {
        role: "app-dev".into(),
        writable_roots: vec![work.clone()],
        network: Some(Network::Denied),
        local_ports: vec![app_port], // only the app port is within territory
        ..Default::default()
    };

    // The agent's trajectory: open a secret fd and hold it, hit the app (within),
    // and run curl (an exfil tool). All observed from outside.
    let script = format!(
        "exec 7< {ssh}/id_demo; curl -s -o /dev/null http://127.0.0.1:{app_port}/; sleep 1.2"
    );
    let be = LandlockBackend;
    let mut child = be
        .spawn(&policy, &["/bin/sh".into(), "-c".into(), script])
        .expect("spawn confined agent");
    let pid = child.id();

    let mut collectors: Vec<Box<dyn Collector>> = vec![
        Box::new(NetworkCollector::for_policy(pid, &policy)),
        Box::new(SecretCollector::for_policy(pid, &policy)),
        Box::new(ProcessCollector::for_policy(pid, &policy)),
    ];

    eprintln!("=== effect log (role={}, pid={pid}) ===", policy.role);
    // Record everything that crosses a boundary (outside OR denied).
    let mut sink = FilterSink::new(JsonlSink::new(std::io::stdout()), RecordMode::Boundary);
    let code = observe_until_exit(&mut child, &mut collectors, &mut sink, Duration::from_millis(80));
    eprintln!("=== agent exited: {code} ===");

    std::fs::remove_dir_all(&work).ok();
    std::fs::remove_file(format!("{ssh}/id_demo")).ok();
}
