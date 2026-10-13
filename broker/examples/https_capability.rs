//! HTTPS via the broker, no MITM (Linux). The agent speaks plain HTTP to the
//! broker; the broker does the real HTTPS and injects the secret. The agent
//! never does TLS and never holds the token.
//! `cargo run -p seisin-sandbox-broker --example https_capability` (needs curl + network)

use seisin_sandbox_broker::{Broker, Capability, Injection};
use seisin_sandbox_core::{Backend, JsonlSink, Network, Policy};
use seisin_sandbox_linux::LandlockBackend;
use std::thread;
use std::time::Duration;

fn main() {
    let run_token = "run-token-only-the-agent-has";
    let broker = Broker::new("qa", vec![])
        .with_auth(run_token)
        .with_capabilities(vec![Capability {
            prefix: "/ex".into(),
            upstream_base: "https://example.com".into(),
            injections: vec![Injection {
                host: None,
                header: "Authorization".into(),
                value: "Bearer token-the-agent-never-sees".into(),
            }],
        }]);
    let (listener, broker_port) = broker.bind(0).unwrap();
    thread::spawn(move || {
        let mut sink = JsonlSink::new(std::io::stdout());
        broker.serve(listener, &mut sink);
    });
    thread::sleep(Duration::from_millis(400));

    let work = std::env::temp_dir().join(format!("sbx-https-{}", std::process::id()));
    std::fs::create_dir_all(&work).unwrap();
    let policy = Policy {
        role: "qa".into(),
        writable_roots: vec![work.clone()],
        network: Some(Network::Denied),
        local_ports: vec![broker_port], // only the broker; not 443
        ..Default::default()
    };
    let be = LandlockBackend;
    let pass = |b: bool| if b { "PASS" } else { "FAIL" };

    println!("agent may reach only broker port {broker_port}; TLS token lives only in the broker\n");

    // via the broker WITH the run token: plain HTTP to broker -> HTTPS upstream
    let out = work.join("via");
    let rc = be.run(&policy, &[
        "curl".into(), "-sS".into(), "-o".into(), out.to_string_lossy().into(),
        "-H".into(), format!("X-Seisin-Auth: {run_token}"),
        format!("http://127.0.0.1:{broker_port}/ex/"),
    ]).map(|o| o.exit_code).unwrap_or(-1);
    let body = std::fs::read_to_string(&out).unwrap_or_default();
    let ok = rc == 0 && body.contains("Example Domain");
    println!("https via broker (token):    rc={rc} got-example-domain={}  {}", body.contains("Example Domain"), pass(ok));

    // WITHOUT the token: a stray process reaching the port is rejected (403)
    let noauth = work.join("noauth");
    be.run(&policy, &[
        "curl".into(), "-s".into(), "-o".into(), noauth.to_string_lossy().into(),
        format!("http://127.0.0.1:{broker_port}/ex/"),
    ]).ok();
    let nbody = std::fs::read_to_string(&noauth).unwrap_or_default();
    println!("https via broker (no token): got-example-domain={}  {}", nbody.contains("Example Domain"), pass(!nbody.contains("Example Domain")));

    // direct HTTPS: blocked (443 not granted)
    let rc = be.run(&policy, &[
        "curl".into(), "-s".into(), "--max-time".into(), "4".into(),
        "-o".into(), work.join("direct").to_string_lossy().into(),
        "https://example.com/".into(),
    ]).map(|o| o.exit_code).unwrap_or(-1);
    println!("direct https:       rc={rc}  {}", pass(rc != 0));

    std::fs::remove_dir_all(&work).ok();
}
