//! End-to-end proof of the single gateway (Linux). Run on a Landlock kernel:
//! `cargo run -p seisin-sandbox-broker --example gateway_demo`. Needs curl.
//!
//! - upstream: returns "AUTHENTICATED" only if it receives the right secret.
//! - broker: holds the secret, injects it, forwards. Runs OUTSIDE the box.
//! - agent: confined; may reach ONLY the broker's port (not the upstream's).
//!
//! Expect: via the broker the agent gets "AUTHENTICATED" without ever holding
//! the token; a direct connection to the upstream is blocked by the sandbox.

use seisin_sandbox_broker::{Broker, Injection};
use seisin_sandbox_core::{Backend, JsonlSink, Network, Policy};
use seisin_sandbox_linux::LandlockBackend;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

const SECRET: &str = "Bearer s3cr3t-the-agent-never-sees";

fn main() {
    // --- upstream: authenticates on the secret header -----------------------
    let up = TcpListener::bind("127.0.0.1:0").unwrap();
    let up_port = up.local_addr().unwrap().port();
    thread::spawn(move || {
        for s in up.incoming().flatten() {
            handle_upstream(s);
        }
    });

    // --- broker: holds the secret, injects it, forwards ---------------------
    let broker = Broker::new(
        "qa",
        vec![Injection { host: None, header: "Authorization".into(), value: SECRET.into() }],
    );
    let (listener, broker_port) = broker.bind(0).unwrap();
    thread::spawn(move || {
        let mut sink = JsonlSink::new(std::io::stdout());
        broker.serve(listener, &mut sink);
    });

    thread::sleep(Duration::from_millis(500));

    // --- agent: confined, may reach ONLY the broker port --------------------
    let work = std::env::temp_dir().join(format!("sbx-gw-{}", std::process::id()));
    std::fs::create_dir_all(&work).unwrap();
    let policy = Policy {
        role: "qa".into(),
        writable_roots: vec![work.clone()],
        network: Some(Network::Denied),
        local_ports: vec![broker_port], // NOT up_port
        ..Default::default()
    };
    let be = LandlockBackend;

    println!("secret lives only in the broker; agent policy grants port {broker_port} only\n");

    // via the broker (proxy): should authenticate. Write to a writable file in
    // the box, then read it back, so the proof is the file content.
    let out = work.join("via_broker.txt");
    let rc = be.run(&policy, &[
        "curl".into(), "-sS".into(), "-o".into(), out.to_string_lossy().into(),
        "-x".into(), format!("http://127.0.0.1:{broker_port}"),
        format!("http://127.0.0.1:{up_port}/"),
    ]).map(|o| o.exit_code).unwrap_or(-1);
    let body = std::fs::read_to_string(&out).unwrap_or_default();
    let ok_broker = body.trim() == "AUTHENTICATED";
    println!("via broker:   rc={rc} body={:?}  {}", body.trim(), pass(ok_broker));

    // direct to the upstream (no proxy): should be blocked by the sandbox
    let direct = work.join("direct");
    let rc = be.run(&policy, &[
        "curl".into(), "-s".into(), "--max-time".into(), "3".into(),
        "-o".into(), direct.to_string_lossy().into(),
        format!("http://127.0.0.1:{up_port}/"),
    ]).map(|o| o.exit_code).unwrap_or(-1);
    let direct_body = std::fs::read_to_string(&direct).unwrap_or_default();
    let blocked = rc != 0 && direct_body.trim().is_empty();
    println!("direct egress: rc={rc} body={:?}  {}", direct_body.trim(), pass(blocked));

    // the agent never held the secret: it is not in policy/command/env we passed
    let leaked = body.contains("s3cr3t") || direct_body.contains("s3cr3t");
    println!("agent saw the token: {}  {}", leaked, pass(!leaked));

    let _ = std::fs::remove_dir_all(&work);
}

fn pass(b: bool) -> &'static str { if b { "PASS" } else { "FAIL" } }

fn handle_upstream(stream: TcpStream) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut stream = stream;
    let mut authed = false;
    let mut line = String::new();
    // request line
    let _ = reader.read_line(&mut line);
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" || h == "\n" {
            break;
        }
        if let Some((k, v)) = h.trim_end().split_once(':') {
            if k.trim().eq_ignore_ascii_case("authorization")
                && v.trim() == SECRET
            {
                authed = true;
            }
        }
    }
    let body = if authed { "AUTHENTICATED" } else { "DENIED" };
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(resp.as_bytes());
}
