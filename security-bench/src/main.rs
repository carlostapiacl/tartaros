//! seisin-security-bench — run the conformance corpus against the sandbox.
//!
//! Each scenario (a TOML contract in `corpus/`) has: a policy, a fixture, a
//! forbidden operation that must NOT succeed, a legitimate control that must,
//! and real-effect assertions (a protected file is unchanged, a marker is
//! absent). We check the actual effect, not just an exit code — a sandbox that
//! bloquea todo y rompe el trabajo legítimo no sirve.
//!
//! Run: `cargo run -p seisin-security-bench -- corpus`

use seisin_sandbox_core::{Backend, Network, Policy};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
type Be = seisin_sandbox_linux::LandlockBackend;
#[cfg(target_os = "macos")]
type Be = seisin_sandbox_macos::SeatbeltBackend;

#[cfg(target_os = "linux")]
const BACKEND: Be = seisin_sandbox_linux::LandlockBackend;
#[cfg(target_os = "macos")]
const BACKEND: Be = seisin_sandbox_macos::SeatbeltBackend;

const OS: &str = if cfg!(target_os = "linux") { "linux" } else { "macos" };

#[derive(Deserialize)]
struct Contract {
    id: String,
    category: String,
    severity: String,
    #[serde(default)]
    os: Vec<String>,
    policy: PolicySpec,
    #[serde(default)]
    fixture: Vec<FixtureItem>,
    #[serde(default)]
    server: Vec<ServerSpec>,
    #[serde(default)]
    unix_server: Vec<UnixServerSpec>,
    #[serde(default)]
    broker: Option<BrokerSpec>,
    attack: Op,
    control: Op,
    #[serde(default)]
    assert: AssertSpec,
}

#[derive(Deserialize, Default)]
struct PolicySpec {
    #[serde(default)]
    writable_roots: Vec<String>,
    #[serde(default)]
    read_denies: Vec<String>,
    #[serde(default)]
    local_ports: Vec<u16>,
    #[serde(default)]
    materialize_absent_handoff: bool,
    #[serde(default)]
    isolate_process_info: bool,
    #[serde(default)]
    timeout_secs: Option<u64>,
    #[serde(default)]
    max_memory_bytes: Option<u64>,
    #[serde(default)]
    max_processes: Option<u64>,
    #[serde(default)]
    deny_unix_sockets: bool,
}

/// A loopback TCP server the runner starts for network scenarios.
#[derive(Deserialize)]
struct ServerSpec {
    port: u16,
}

/// A unix-domain socket server the runner starts for IPC scenarios.
#[derive(Deserialize)]
struct UnixServerSpec {
    path: String,
}

/// A broker the runner starts for credential scenarios. The secret lives only
/// here — never in the policy or the agent's command.
#[derive(Deserialize)]
struct BrokerSpec {
    port: u16,
    token: String,
    #[serde(default)]
    capability: Vec<CapSpec>,
}

#[derive(Deserialize)]
struct CapSpec {
    prefix: String,
    upstream_base: String,
    inject_header: String,
    inject_value: String,
}

#[derive(Deserialize)]
struct FixtureItem {
    path: String,
    #[serde(default)]
    content: String,
    #[serde(default)]
    dir: bool,
    /// If set, create `path` as a symlink pointing here.
    #[serde(default)]
    symlink_to: Option<String>,
}

#[derive(Deserialize)]
struct Op {
    cmd: String,
    /// If set, the op must exit with exactly this code (used for lifecycle
    /// guarantees like a timeout → 124). Otherwise the default applies: an
    /// attack must fail (exit != 0), a control must succeed (exit == 0).
    #[serde(default)]
    expect_exit: Option<i32>,
}

#[derive(Deserialize, Default)]
struct AssertSpec {
    /// This file's content must be identical to what the fixture wrote.
    unchanged: Option<String>,
    /// This path must not exist after the run.
    absent: Option<String>,
}

struct Outcome {
    id: String,
    category: String,
    severity: String,
    violation: bool,  // the forbidden op succeeded (security failure)
    control_broke: bool, // the legitimate op failed (usability failure)
    passed: bool,
    detail: String,
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "corpus".into());
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("reading {dir}: {e}"))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "toml").unwrap_or(false))
        .collect();
    files.sort();

    println!("seisin-security-bench · backend={OS}\n");
    let mut outcomes = Vec::new();
    let mut infra_errors = 0usize; // invalid/unreadable contracts
    let mut skipped = 0usize;      // not for this OS
    for f in &files {
        let text = match std::fs::read_to_string(f) {
            Ok(t) => t,
            Err(e) => { println!("  !! {}: read error: {e}", f.display()); infra_errors += 1; continue; }
        };
        let c: Contract = match toml::from_str(&text) {
            Ok(c) => c,
            Err(e) => {
                println!("  !! {}: parse error (INFRA_ERROR): {e}", f.display());
                infra_errors += 1;
                continue;
            }
        };
        if !c.os.is_empty() && !c.os.iter().any(|o| o == OS) {
            println!("  -- {} (SKIPPED: not for {OS})", c.id);
            skipped += 1;
            continue;
        }
        outcomes.push(run_scenario(c));
    }

    println!("\n{:<36} {:<8} {}", "scenario", "sev", "result");
    println!("{}", "-".repeat(64));
    for o in &outcomes {
        let r = if o.passed { "PASS" } else if o.violation { "VIOLATION" } else { "control-broke" };
        println!("{:<36} {:<8} {}  {}", o.id, o.severity, r, o.detail);
    }

    let total = outcomes.len();
    let passed = outcomes.iter().filter(|o| o.passed).count();
    let violations = outcomes.iter().filter(|o| o.violation).count();
    let broke = outcomes.iter().filter(|o| o.control_broke).count();
    let crit_viol = outcomes.iter().filter(|o| o.violation && o.severity == "critical").count();
    println!("\n== scorecard ==");
    println!("  scenarios run:           {total}");
    println!("  PASS:                    {passed}/{total}");
    println!("  VIOLATION:               {violations}  (critical: {crit_viol})  [target 0]");
    println!("  CONTROL_BROKE:           {broke}  [target 0]");
    println!("  INFRA_ERROR:             {infra_errors}  [target 0]");
    println!("  SKIPPED (other OS):      {skipped}");

    // write a JSON report
    let _ = std::fs::create_dir_all("reports");
    let mut j = String::from("{\n");
    j.push_str(&format!("  \"os\": \"{OS}\",\n  \"total\": {total},\n  \"passed\": {passed},\n  \"violations\": {violations},\n  \"critical_violations\": {crit_viol},\n  \"control_broken\": {broke},\n  \"scenarios\": [\n"));
    for (i, o) in outcomes.iter().enumerate() {
        j.push_str(&format!(
            "    {{\"id\":\"{}\",\"category\":\"{}\",\"severity\":\"{}\",\"passed\":{},\"violation\":{},\"control_broke\":{}}}{}\n",
            o.id, o.category, o.severity, o.passed, o.violation, o.control_broke,
            if i + 1 < outcomes.len() { "," } else { "" }
        ));
    }
    j.push_str("  ]\n}\n");
    let _ = std::fs::write("reports/last.json", j);
    println!("\nreport: reports/last.json");

    // CI gate: fail on ANY violation, broken control, or infra error — not just
    // critical violations (review P1). A green run means every scenario actually
    // executed and passed.
    let _ = crit_viol;
    if violations > 0 || broke > 0 || infra_errors > 0 {
        eprintln!("\nFAIL: {violations} violation(s), {broke} broken control(s), {infra_errors} infra error(s)");
        std::process::exit(1);
    }
    println!("\nOK: all {total} scenarios passed ({skipped} skipped for other OS)");
}

fn run_scenario(c: Contract) -> Outcome {
    let root = std::env::temp_dir().join(format!("secbench-{}-{}", c.id, std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let root_s = root.canonicalize().unwrap().to_string_lossy().into_owned();
    let sub = |s: &str| s.replace("{root}", &root_s);

    // fixtures
    let mut fixture_content: BTreeMap<String, String> = BTreeMap::new();
    for fi in &c.fixture {
        let p = sub(&fi.path);
        if let Some(parent) = Path::new(&p).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Some(target) = &fi.symlink_to {
            #[cfg(unix)]
            let _ = std::os::unix::fs::symlink(sub(target), &p);
        } else if fi.dir {
            let _ = std::fs::create_dir_all(&p);
        } else {
            let _ = std::fs::write(&p, &fi.content);
            fixture_content.insert(p, fi.content.clone());
        }
    }

    // start any loopback servers the scenario needs (network cases)
    let mut servers = Vec::new();
    for s in &c.server {
        if let Ok(l) = std::net::TcpListener::bind(("127.0.0.1", s.port)) {
            let l2 = l.try_clone().ok();
            std::thread::spawn(move || {
                for stream in l.incoming().flatten() {
                    let mut st = stream;
                    use std::io::Write;
                    let _ = st.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
                }
            });
            servers.push(l2);
        }
    }
    // unix-domain socket servers (IPC scenarios)
    let mut unix_paths = Vec::new();
    for u in &c.unix_server {
        let path = sub(&u.path);
        let _ = std::fs::remove_file(&path);
        if let Some(parent) = Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(l) = std::os::unix::net::UnixListener::bind(&path) {
            std::thread::spawn(move || {
                for stream in l.incoming().flatten() {
                    use std::io::Write;
                    let mut st = stream;
                    let _ = st.write_all(b"ok");
                }
            });
            unix_paths.push(path);
        }
    }
    // broker (credential scenarios): secret lives only in the broker config.
    if let Some(bs) = &c.broker {
        use seisin_sandbox_broker::{Broker, Capability, Injection};
        let caps: Vec<Capability> = bs
            .capability
            .iter()
            .map(|cp| Capability {
                prefix: cp.prefix.clone(),
                upstream_base: sub(&cp.upstream_base),
                methods: vec!["GET".into()],
                injections: vec![Injection {
                    host: None,
                    header: cp.inject_header.clone(),
                    value: cp.inject_value.clone(),
                }],
            })
            .collect();
        let broker = Broker::new("bench", vec![]).with_auth(bs.token.clone()).with_capabilities(caps);
        if let Ok(l) = std::net::TcpListener::bind(("127.0.0.1", bs.port)) {
            std::thread::spawn(move || {
                let mut sink = seisin_sandbox_core::VecSink::default();
                let _ = broker.serve(l, &mut sink);
            });
        }
    }
    std::thread::sleep(std::time::Duration::from_millis(200));

    let policy = Policy {
        role: "bench".into(),
        writable_roots: c.policy.writable_roots.iter().map(|s| PathBuf::from(sub(s))).collect(),
        read_denies: c.policy.read_denies.iter().map(|s| PathBuf::from(sub(s))).collect(),
        local_ports: c.policy.local_ports.clone(),
        network: Some(Network::Denied),
        materialize_absent_handoff: c.policy.materialize_absent_handoff,
        isolate_process_info: c.policy.isolate_process_info,
        timeout: c.policy.timeout_secs.map(std::time::Duration::from_secs),
        max_memory_bytes: c.policy.max_memory_bytes,
        max_processes: c.policy.max_processes,
        deny_unix_sockets: c.policy.deny_unix_sockets,
        ..Default::default()
    };

    let run = |cmd: &str| -> i32 {
        BACKEND
            .run(&policy, &["/bin/sh".into(), "-c".into(), sub(cmd)])
            .map(|o| o.exit_code)
            .unwrap_or(-1)
    };

    // attack: forbidden op must NOT succeed (or must exit with expect_exit)
    let attack_rc = run(&c.attack.cmd);
    let attack_succeeded = match c.attack.expect_exit {
        Some(code) => attack_rc != code, // "succeeded" = guarantee NOT met
        None => attack_rc == 0,
    };

    // control: legitimate op must succeed (or match expect_exit)
    let control_rc = run(&c.control.cmd);
    let control_ok = match c.control.expect_exit {
        Some(code) => control_rc == code,
        None => control_rc == 0,
    };

    drop(servers);
    for p in &unix_paths {
        let _ = std::fs::remove_file(p);
    }

    // real-effect assertions
    let mut effect_ok = true;
    let mut detail = String::new();
    if let Some(u) = &c.assert.unchanged {
        let p = sub(u);
        let now = std::fs::read_to_string(&p).unwrap_or_default();
        let orig = fixture_content.get(&p).cloned().unwrap_or_default();
        if now != orig {
            effect_ok = false;
            detail = format!("{u} changed");
        }
    }
    if let Some(a) = &c.assert.absent {
        if Path::new(&sub(a)).exists() {
            effect_ok = false;
            detail = format!("{a} exists");
        }
    }

    let violation = attack_succeeded || !effect_ok;
    let control_broke = !control_ok;
    let passed = !violation && !control_broke;
    if detail.is_empty() {
        detail = format!("attack rc={attack_rc} control rc={control_rc}");
    }

    let _ = std::fs::remove_dir_all(&root);
    Outcome { id: c.id, category: c.category, severity: c.severity, violation, control_broke, passed, detail }
}
