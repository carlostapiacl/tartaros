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
}

#[derive(Deserialize)]
struct FixtureItem {
    path: String,
    #[serde(default)]
    content: String,
    #[serde(default)]
    dir: bool,
}

#[derive(Deserialize)]
struct Op {
    cmd: String,
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
    for f in &files {
        let text = std::fs::read_to_string(f).unwrap();
        let c: Contract = match toml::from_str(&text) {
            Ok(c) => c,
            Err(e) => {
                println!("  !! {}: parse error: {e}", f.display());
                continue;
            }
        };
        if !c.os.is_empty() && !c.os.iter().any(|o| o == OS) {
            println!("  -- {} (skip: not for {OS})", c.id);
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
    println!("  scenarios:               {total}");
    println!("  passed:                  {passed}/{total}");
    println!("  security violations:     {violations}  (critical: {crit_viol})  [target 0]");
    println!("  legitimate ops broken:   {broke}  [target 0]");

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

    if crit_viol > 0 {
        std::process::exit(1);
    }
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
        if fi.dir {
            let _ = std::fs::create_dir_all(&p);
        } else {
            if let Some(parent) = Path::new(&p).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(&p, &fi.content);
            fixture_content.insert(p, fi.content.clone());
        }
    }

    let policy = Policy {
        role: "bench".into(),
        writable_roots: c.policy.writable_roots.iter().map(|s| PathBuf::from(sub(s))).collect(),
        read_denies: c.policy.read_denies.iter().map(|s| PathBuf::from(sub(s))).collect(),
        local_ports: c.policy.local_ports.clone(),
        network: Some(Network::Denied),
        materialize_absent_handoff: c.policy.materialize_absent_handoff,
        isolate_process_info: c.policy.isolate_process_info,
        ..Default::default()
    };

    let run = |cmd: &str| -> i32 {
        BACKEND
            .run(&policy, &["/bin/sh".into(), "-c".into(), sub(cmd)])
            .map(|o| o.exit_code)
            .unwrap_or(-1)
    };

    // attack: the forbidden op must NOT succeed
    let attack_rc = run(&c.attack.cmd);
    let attack_succeeded = attack_rc == 0;

    // control: the legitimate op must succeed
    let control_rc = run(&c.control.cmd);
    let control_ok = control_rc == 0;

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
