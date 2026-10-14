//! tartaros-bench — run the conformance corpus against the sandbox.
//!
//! Each scenario (a TOML contract in `corpus/`) has: a policy, a fixture, a
//! forbidden operation that must NOT succeed, a legitimate control that must,
//! and real-effect assertions (a protected file is unchanged, a marker is
//! absent). We check the actual effect, not just an exit code — a sandbox that
//! bloquea todo y rompe el trabajo legítimo no sirve.
//!
//! Run: `cargo run -p tartaros-bench -- corpus`

use tartaros_core::{Backend, Network, Policy};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
type Be = tartaros_linux::LandlockBackend;
#[cfg(target_os = "macos")]
type Be = tartaros_macos::SeatbeltBackend;

#[cfg(target_os = "linux")]
const BACKEND: Be = tartaros_linux::LandlockBackend;
#[cfg(target_os = "macos")]
const BACKEND: Be = tartaros_macos::SeatbeltBackend;

const OS: &str = if cfg!(target_os = "linux") { "linux" } else { "macos" };

#[derive(Deserialize)]
struct Contract {
    id: String,
    category: String,
    severity: String,
    #[serde(default)]
    os: Vec<String>,
    /// Host capabilities this scenario needs to be a meaningful test, e.g.
    /// "landlock", "cgroup", "userns". If the host lacks one, the scenario is
    /// reported UNSUPPORTED (not PASS, not a failure) — a green run must never
    /// hide "couldn't actually test here".
    #[serde(default)]
    requires: Vec<String>,
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
    read_allows: Vec<String>,
    #[serde(default)]
    write_denies: Vec<String>,
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
    max_cpu_secs: Option<u64>,
    #[serde(default)]
    deny_unix_sockets: bool,
    #[serde(default)]
    isolate_pids: bool,
    #[serde(default)]
    isolate_network: bool,
    #[serde(default)]
    harden_syscalls: bool,
    #[serde(default)]
    strict: bool,
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
    /// Seconds to wait after the run before checking the assertions. Lets a
    /// lifecycle escape (e.g. a daemon that would act only after the sandbox
    /// exits) reveal itself before we assert teardown killed it.
    #[serde(default)]
    settle_secs: Option<u64>,
}

struct Outcome {
    id: String,
    category: String,
    severity: String,
    violation: bool,  // the forbidden op succeeded (security failure)
    control_broke: bool, // the legitimate op failed (usability failure)
    /// The backend could not even launch the command (spawn/Landlock error).
    /// This is NOT a blocked attack — conflating the two would let a scenario
    /// whose process never started look like a pass. Counted as INFRA_ERROR.
    infra_error: bool,
    passed: bool,
    detail: String,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // --perf needs no corpus; handle it before reading any directory.
    if args.iter().any(|a| a == "--perf") {
        let n = args.iter().filter_map(|a| a.parse::<usize>().ok()).next().unwrap_or(50);
        run_perf(n);
        return;
    }

    let mutate = args.iter().any(|a| a == "--mutate");
    // --require-caps <comma,list>: host capabilities a full-coverage certification
    // run demands. Any listed cap absent on this host => FAIL (ADV-05), so a green
    // exit can never be cited when scenarios were silently UNSUPPORTED. Omit it for
    // a best-effort run on a capability-poor host (tests what it can).
    let require_caps: Vec<String> = args
        .iter()
        .position(|a| a == "--require-caps")
        .and_then(|i| args.get(i + 1))
        .map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();
    // The corpus dir is the first non-flag, non-numeric positional argument,
    // excluding the value that follows --require-caps (not a positional).
    let rc_val_idx = args.iter().position(|a| a == "--require-caps").map(|i| i + 1);
    let dir = args
        .iter()
        .enumerate()
        .find(|(i, a)| Some(*i) != rc_val_idx && !a.starts_with("--") && a.parse::<usize>().is_err())
        .map(|(_, a)| a.clone())
        .unwrap_or_else(|| "corpus".into());
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("reading {dir}: {e}"))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "toml").unwrap_or(false))
        .collect();
    files.sort();

    if mutate {
        run_mutations(&files);
        return;
    }

    println!("tartaros-bench · backend={OS}\n");
    let env = environment();
    // Host capabilities a scenario may require to be meaningful.
    let has_cap = |name: &str| match name {
        "landlock" | "landlock-net" => env.landlock || OS == "macos",
        "cgroup" => env.cgroup_v2,
        "userns" => env.userns,
        _ => true, // unknown requirement: don't silently skip, let it run
    };
    let mut outcomes = Vec::new();
    let mut infra_errors = 0usize; // invalid/unreadable contracts
    let mut skipped = 0usize;      // not for this OS
    let mut unsupported = 0usize;  // host lacks a required capability
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
        if let Some(missing) = c.requires.iter().find(|r| !has_cap(r)) {
            println!("  ~~ {} (UNSUPPORTED: host lacks {missing})", c.id);
            unsupported += 1;
            continue;
        }
        outcomes.push(run_scenario(c));
    }

    println!("\n{:<36} {:<8} {}", "scenario", "sev", "result");
    println!("{}", "-".repeat(64));
    for o in &outcomes {
        let r = if o.passed { "PASS" } else if o.violation { "VIOLATION" } else if o.infra_error { "INFRA_ERROR" } else { "control-broke" };
        println!("{:<36} {:<8} {}  {}", o.id, o.severity, r, o.detail);
    }

    let total = outcomes.len();
    let passed = outcomes.iter().filter(|o| o.passed).count();
    let violations = outcomes.iter().filter(|o| o.violation).count();
    let broke = outcomes.iter().filter(|o| o.control_broke).count();
    let crit_viol = outcomes.iter().filter(|o| o.violation && o.severity == "critical").count();
    // Backend-launch failures found while running scenarios add to the file-level
    // infra errors (a scenario whose process never started is NOT a pass).
    infra_errors += outcomes.iter().filter(|o| o.infra_error).count();
    println!("\n== scorecard ==");
    println!("  scenarios run:           {total}");
    println!("  PASS:                    {passed}/{total}");
    println!("  VIOLATION:               {violations}  (critical: {crit_viol})  [target 0]");
    println!("  CONTROL_BROKE:           {broke}  [target 0]");
    println!("  INFRA_ERROR:             {infra_errors}  [target 0]");
    println!("  SKIPPED (other OS):      {skipped}");
    println!("  UNSUPPORTED (host caps): {unsupported}");
    // Coverage of the scenarios MEANT for this OS (ran vs. unsupported-by-host).
    // A high UNSUPPORTED count means this host certified little, even if green —
    // make that legible instead of hiding behind a single exit code (ADV-05).
    let applicable = total + unsupported;
    println!("  coverage:                {total}/{applicable} applicable scenarios ran");

    // Environment stamp: a scorecard is only citeable if it says WHERE it ran and
    // which enforcement primitives the host actually offered (a PASS on a host
    // missing Landlock/cgroup is not the same guarantee). Printed and recorded.
    println!("\nenvironment: {} · kernel {} · tartaros-bench {}", env.os, env.kernel, env.version);
    println!("host caps:  landlock={} cgroup_v2={} userns={}", env.landlock, env.cgroup_v2, env.userns);

    // write a JSON report
    let _ = std::fs::create_dir_all("reports");
    let mut j = String::from("{\n");
    j.push_str(&format!(
        "  \"os\": \"{OS}\",\n  \"environment\": {{\"os\":\"{}\",\"kernel\":\"{}\",\"tool_version\":\"{}\",\"unix_time\":{},\"caps\":{{\"landlock\":{},\"cgroup_v2\":{},\"userns\":{}}}}},\n  \"total\": {total},\n  \"passed\": {passed},\n  \"violations\": {violations},\n  \"critical_violations\": {crit_viol},\n  \"control_broken\": {broke},\n  \"scenarios\": [\n",
        env.os, env.kernel, env.version, env.unix_time, env.landlock, env.cgroup_v2, env.userns
    ));
    j.push_str(&format!("  \"skipped\": {skipped},\n  \"unsupported\": {unsupported},\n"));
    for (i, o) in outcomes.iter().enumerate() {
        j.push_str(&format!(
            "    {{\"id\":\"{}\",\"category\":\"{}\",\"severity\":\"{}\",\"passed\":{},\"violation\":{},\"control_broke\":{},\"infra_error\":{}}}{}\n",
            o.id, o.category, o.severity, o.passed, o.violation, o.control_broke, o.infra_error,
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
    // Minimum-coverage gate (adversarial-audit P1): a run that verified NO
    // guarantee must never certify green. If nothing actually passed — e.g. every
    // scenario was skipped or unsupported, or the corpus was empty — that is not
    // success, it is "we tested nothing here".
    if passed == 0 {
        eprintln!(
            "\nFAIL: 0 scenarios passed ({skipped} skipped, {unsupported} unsupported) — \
             no guarantee was actually verified on this host; not a green run."
        );
        std::process::exit(1);
    }
    // Required-coverage gate (ADV-05): when the caller demands a full-coverage
    // certification (`--require-caps`), a host missing any demanded capability must
    // FAIL — otherwise its scenarios came back UNSUPPORTED and a green exit would
    // overstate what was verified. `has_cap` maps the cap name to the host stamp.
    if !require_caps.is_empty() {
        // Dedicated check: an UNKNOWN cap name (a typo) counts as missing, so a
        // bogus requirement fails loudly instead of passing like `has_cap` lets an
        // unknown scenario requirement run.
        let cap_present = |c: &str| match c {
            "landlock" | "landlock-net" => env.landlock || OS == "macos",
            "cgroup" => env.cgroup_v2,
            "userns" => env.userns,
            _ => false,
        };
        let missing: Vec<&str> = require_caps.iter().map(|s| s.as_str()).filter(|c| !cap_present(c)).collect();
        if !missing.is_empty() {
            eprintln!(
                "\nFAIL: --require-caps not met on this host: missing [{}] (unsupported={unsupported}). \
                 A full-coverage certification cannot be claimed here; re-run on a host with these \
                 capabilities or drop the requirement for a best-effort run.",
                missing.join(", ")
            );
            std::process::exit(1);
        }
    }
    let cov_note = if require_caps.is_empty() { String::new() } else { format!(", require-caps [{}] met", require_caps.join(", ")) };
    println!("\nOK: all {passed} scenarios passed ({skipped} skipped, {unsupported} unsupported, coverage {total}/{applicable}{cov_note})");
}

/// A deliberate weakening of a policy, used by `--mutate` to prove the corpus
/// actually exercises each enforcement: removing a protection must make at least
/// one scenario's attack succeed (flip to VIOLATION). A mutation that flips
/// nothing is a blind spot in the suite. Mutations weaken the POLICY the runner
/// passes — never the backend — so the real enforcement is exercised.
#[derive(Clone, Copy)]
enum Mutation {
    DropReadDenies,
    GrantNetwork,
    DropIsolateNet,
    DropIsolatePids,
    RaiseProcLimit,
    RaiseMemLimit,
}

impl Mutation {
    const ALL: [Mutation; 6] = [
        Mutation::DropReadDenies,
        Mutation::GrantNetwork,
        Mutation::DropIsolateNet,
        Mutation::DropIsolatePids,
        Mutation::RaiseProcLimit,
        Mutation::RaiseMemLimit,
    ];
    fn name(self) -> &'static str {
        match self {
            Mutation::DropReadDenies => "drop-read-denies",
            Mutation::GrantNetwork => "grant-network",
            Mutation::DropIsolateNet => "drop-isolate-net",
            Mutation::DropIsolatePids => "drop-isolate-pids",
            Mutation::RaiseProcLimit => "raise-proc-limit",
            Mutation::RaiseMemLimit => "raise-mem-limit",
        }
    }
    /// Does the scenario rely on the protection this mutation removes?
    fn applies(self, c: &Contract) -> bool {
        match self {
            Mutation::DropReadDenies => !c.policy.read_denies.is_empty(),
            Mutation::GrantNetwork => !c.server.is_empty() || c.broker.is_some(),
            Mutation::DropIsolateNet => c.policy.isolate_network,
            Mutation::DropIsolatePids => c.policy.isolate_pids,
            Mutation::RaiseProcLimit => c.policy.max_processes.is_some(),
            Mutation::RaiseMemLimit => c.policy.max_memory_bytes.is_some(),
        }
    }
    fn weaken(self, p: &mut Policy) {
        match self {
            Mutation::DropReadDenies => p.read_denies.clear(),
            Mutation::GrantNetwork => p.network = Some(Network::Allowed),
            Mutation::DropIsolateNet => p.isolate_network = false,
            Mutation::DropIsolatePids => p.isolate_pids = false,
            Mutation::RaiseProcLimit => p.max_processes = None,
            Mutation::RaiseMemLimit => p.max_memory_bytes = None,
        }
    }
}

/// Self-describing environment stamp for a scorecard (read-only probes).
struct Env {
    os: String,
    kernel: String,
    version: String,
    unix_time: u64,
    landlock: bool,
    cgroup_v2: bool,
    userns: bool,
}

fn environment() -> Env {
    let kernel = std::process::Command::new("uname")
        .arg("-r")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into());
    let unix_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Linux capability probes — read-only, no side effects.
    let landlock = std::fs::read_to_string("/sys/kernel/security/lsm")
        .map(|s| s.split(',').any(|l| l.trim() == "landlock"))
        .unwrap_or(false);
    // cgroup v2 must be USABLE, not merely present: a non-privileged container
    // has /sys/fs/cgroup/cgroup.controllers yet cannot create a child cgroup, so
    // a process cap would silently degrade. Probe by actually creating one.
    let cgroup_v2 = Path::new("/sys/fs/cgroup/cgroup.controllers").exists() && {
        let dir = format!("/sys/fs/cgroup/tartaros-bench-probe-{}", std::process::id());
        let ok = std::fs::create_dir(&dir).is_ok();
        if ok {
            let _ = std::fs::remove_dir(&dir);
        }
        ok
    };
    // User namespaces available for unprivileged clone, or we are privileged.
    let userns = std::fs::read_to_string("/proc/sys/user/max_user_namespaces")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(|n| n > 0)
        .unwrap_or(false);
    Env {
        os: OS.to_string(),
        kernel,
        version: env!("CARGO_PKG_VERSION").to_string(),
        unix_time,
        landlock,
        cgroup_v2,
        userns,
    }
}

/// Startup-overhead benchmark: how much latency the sandbox adds per launch.
/// Agents spawn many short confined commands, so this is a real product metric.
/// Times `/bin/true` unsandboxed vs under a minimal policy vs under the hardened
/// (hostile-code) tier, and reports p50/p95. Read-only, no corpus.
fn run_perf(n: usize) {
    use std::time::Instant;
    let env = environment();
    let root = std::env::temp_dir().join(format!("tartaros-perf-{}", std::process::id()));
    let _ = std::fs::create_dir_all(root.join("work"));
    let base = Policy {
        role: "perf".into(),
        writable_roots: vec![root.join("work")],
        network: Some(Network::Denied),
        ..Default::default()
    };
    let mut hardened = base.clone();
    tartaros_core::Profile::HostileCode.apply(&mut hardened);

    let pct = |mut v: Vec<f64>, p: f64| -> f64 {
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        if v.is_empty() { return 0.0; }
        v[(((v.len() - 1) as f64) * p).round() as usize]
    };
    let time_it = |run: &mut dyn FnMut()| -> Vec<f64> {
        // one warmup, then n timed runs (ms)
        run();
        (0..n)
            .map(|_| { let t = Instant::now(); run(); t.elapsed().as_secs_f64() * 1000.0 })
            .collect()
    };

    let cmd = vec!["/bin/true".to_string()];
    let mut raw = || { let _ = std::process::Command::new("/bin/true").status(); };
    let mut sb = || { let _ = BACKEND.run(&base, &cmd); };
    let mut hd = || { let _ = BACKEND.run(&hardened, &cmd); };

    let r = time_it(&mut raw);
    let s = time_it(&mut sb);
    let h = time_it(&mut hd);
    let _ = std::fs::remove_dir_all(&root);

    println!("tartaros-bench · PERF · backend={OS} · n={n}");
    println!("environment: {} · kernel {} · tartaros-bench {}\n", env.os, env.kernel, env.version);
    println!("{:<22} {:>10} {:>10} {:>10}", "launch", "p50 (ms)", "p95 (ms)", "min (ms)");
    println!("{}", "-".repeat(56));
    let row = |label: &str, v: &[f64]| {
        println!("{:<22} {:>10.2} {:>10.2} {:>10.2}", label, pct(v.to_vec(), 0.50), pct(v.to_vec(), 0.95), v.iter().cloned().fold(f64::MAX, f64::min));
    };
    row("unsandboxed", &r);
    row("minimal policy", &s);
    row("hardened (hostile)", &h);
    let base_p50 = pct(r.clone(), 0.50);
    println!("\noverhead vs unsandboxed (p50): minimal +{:.2} ms, hardened +{:.2} ms",
        pct(s.clone(), 0.50) - base_p50, pct(h.clone(), 0.50) - base_p50);

    let _ = std::fs::create_dir_all("reports");
    let j = format!(
        "{{\"os\":\"{}\",\"kernel\":\"{}\",\"n\":{n},\"ms\":{{\"unsandboxed_p50\":{:.3},\"minimal_p50\":{:.3},\"minimal_p95\":{:.3},\"hardened_p50\":{:.3},\"hardened_p95\":{:.3}}}}}\n",
        env.os, env.kernel, pct(r.clone(),0.5), pct(s.clone(),0.5), pct(s.clone(),0.95), pct(h.clone(),0.5), pct(h,0.95)
    );
    let _ = std::fs::write("reports/perf.json", j);
    println!("\nreport: reports/perf.json");
}

fn run_scenario(c: Contract) -> Outcome {
    run_scenario_inner(c, None)
}

/// Mutation testing — "a conformance that cannot fool itself". For each policy
/// weakening, re-run every scenario that relies on the removed protection and
/// require that at least one attack now SUCCEEDS (flips to VIOLATION). A mutation
/// that applies to scenarios yet flips none means the corpus never actually
/// tested that enforcement — a blind spot. Exits non-zero on any blind spot.
fn run_mutations(files: &[PathBuf]) {
    // (path, parsed contract) for contracts valid on this OS
    let loaded: Vec<(PathBuf, Contract)> = files
        .iter()
        .filter_map(|f| std::fs::read_to_string(f).ok().map(|t| (f.clone(), t)))
        .filter_map(|(f, t)| toml::from_str::<Contract>(&t).ok().map(|c| (f, c)))
        .filter(|(_, c)| c.os.is_empty() || c.os.iter().any(|o| o == OS))
        .collect();

    println!("tartaros-bench · MUTATION MODE · backend={OS}\n");
    println!("Each mutation removes one protection; a healthy corpus flips >=1 scenario.\n");
    println!("{:<20} {:<10} {}", "mutation", "flips", "sensitive scenarios");
    println!("{}", "-".repeat(70));

    let mut blind_spots = 0usize;
    for m in Mutation::ALL {
        let applicable: Vec<&PathBuf> = loaded
            .iter()
            .filter(|(_, c)| m.applies(c))
            .map(|(f, _)| f)
            .collect();
        if applicable.is_empty() {
            println!("{:<20} {:<10} (no scenario uses this protection)", m.name(), "n/a");
            continue;
        }
        let mut flipped = Vec::new();
        for f in &applicable {
            // re-parse fresh so each mutated run starts from the clean contract
            let c: Contract = toml::from_str(&std::fs::read_to_string(f).unwrap()).unwrap();
            let o = run_scenario_inner(c, Some(m));
            if o.violation {
                flipped.push(o.id);
            }
        }
        let tag = if flipped.is_empty() { "BLIND-SPOT" } else { "ok" };
        println!(
            "{:<20} {:<10} {} [{}]",
            m.name(),
            format!("{}/{}", flipped.len(), applicable.len()),
            flipped.join(", "),
            tag
        );
        if flipped.is_empty() {
            blind_spots += 1;
        }
    }

    println!("\n== mutation scorecard ==");
    println!("  mutations with a blind spot: {blind_spots}  [target 0]");
    if blind_spots > 0 {
        eprintln!("\nFAIL: {blind_spots} mutation(s) flipped no scenario — the corpus does not actually test that enforcement.");
        std::process::exit(1);
    }
    println!("\nOK: every removable protection is caught by at least one scenario.");
}

fn run_scenario_inner(c: Contract, mutate: Option<Mutation>) -> Outcome {
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
        use tartaros_broker::{Broker, Capability, Injection};
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
                let mut sink = tartaros_core::VecSink::default();
                let _ = broker.serve(l, &mut sink);
            });
        }
    }
    std::thread::sleep(std::time::Duration::from_millis(200));

    let mut policy = Policy {
        role: "bench".into(),
        writable_roots: c.policy.writable_roots.iter().map(|s| PathBuf::from(sub(s))).collect(),
        read_denies: c.policy.read_denies.iter().map(|s| PathBuf::from(sub(s))).collect(),
        read_allows: c.policy.read_allows.iter().map(|s| PathBuf::from(sub(s))).collect(),
        fs_rules: c.policy.write_denies.iter().map(|s| tartaros_core::FsRule { path: PathBuf::from(sub(s)), access: tartaros_core::Access::Deny, even_if_absent: true }).collect(),
        local_ports: c.policy.local_ports.clone(),
        network: Some(Network::Denied),
        materialize_absent_handoff: c.policy.materialize_absent_handoff,
        isolate_process_info: c.policy.isolate_process_info,
        timeout: c.policy.timeout_secs.map(std::time::Duration::from_secs),
        max_memory_bytes: c.policy.max_memory_bytes,
        max_processes: c.policy.max_processes,
        max_cpu_secs: c.policy.max_cpu_secs,
        deny_unix_sockets: c.policy.deny_unix_sockets,
        isolate_pids: c.policy.isolate_pids,
        isolate_network: c.policy.isolate_network,
        harden_syscalls: c.policy.harden_syscalls,
        strict: c.policy.strict,
        ..Default::default()
    };
    // --mutate: deliberately weaken the policy so a corpus blind spot shows up.
    if let Some(m) = mutate {
        m.weaken(&mut policy);
    }

    // Returns Ok(exit_code) when the backend LAUNCHED the command, or Err(reason)
    // when it could not even start it (spawn/Landlock error). The two must not be
    // conflated: a backend failure is infrastructure, not a blocked attack.
    let run = |cmd: &str| -> Result<i32, String> {
        BACKEND
            .run(&policy, &["/bin/sh".into(), "-c".into(), sub(cmd)])
            .map(|o| o.exit_code)
            .map_err(|e| e.reason)
    };
    // Build an INFRA_ERROR outcome (cleaning up first) when the backend couldn't
    // run a command — never report that as pass/violation.
    let infra = |detail: String| -> Outcome {
        let _ = std::fs::remove_dir_all(&root);
        Outcome {
            id: c.id.clone(), category: c.category.clone(), severity: c.severity.clone(),
            violation: false, control_broke: false, infra_error: true, passed: false, detail,
        }
    };

    // attack: forbidden op must NOT succeed (or must exit with expect_exit).
    // In mutation mode the attack may succeed and print fixture data (e.g. a test
    // secret), so suppress its output there — only its exit status matters.
    let attack_cmd = if mutate.is_some() {
        format!("{{ {} ; }} >/dev/null 2>&1", c.attack.cmd)
    } else {
        c.attack.cmd.clone()
    };
    let attack_res = run(&attack_cmd);

    // Mutation run: we only care whether weakening the policy let the attack
    // through (the corpus "noticed" the removed protection). A backend error
    // counts as "did not flip". Skip control and effect assertions.
    if mutate.is_some() {
        let attack_succeeded = match &attack_res {
            Ok(rc) => match c.attack.expect_exit { Some(code) => *rc != code, None => *rc == 0 },
            Err(_) => false,
        };
        drop(servers);
        for p in &unix_paths {
            let _ = std::fs::remove_file(p);
        }
        let _ = std::fs::remove_dir_all(&root);
        return Outcome {
            id: c.id, category: c.category, severity: c.severity,
            violation: attack_succeeded, control_broke: false, infra_error: false,
            passed: !attack_succeeded, detail: format!("attack {attack_res:?}"),
        };
    }

    // A backend that could not launch the attack is INFRA_ERROR, not "blocked".
    let attack_rc = match attack_res {
        Ok(rc) => rc,
        Err(e) => { drop(servers); for p in &unix_paths { let _ = std::fs::remove_file(p); } return infra(format!("attack backend error: {e}")); }
    };
    let attack_succeeded = match c.attack.expect_exit {
        Some(code) => attack_rc != code, // "succeeded" = guarantee NOT met
        None => attack_rc == 0,
    };

    // control: legitimate op must succeed (or match expect_exit)
    let control_rc = match run(&c.control.cmd) {
        Ok(rc) => rc,
        Err(e) => { drop(servers); for p in &unix_paths { let _ = std::fs::remove_file(p); } return infra(format!("control backend error: {e}")); }
    };
    let control_ok = match c.control.expect_exit {
        Some(code) => control_rc == code,
        None => control_rc == 0,
    };

    drop(servers);
    for p in &unix_paths {
        let _ = std::fs::remove_file(p);
    }

    // Let a lifecycle escape surface before asserting teardown killed it.
    if let Some(s) = c.assert.settle_secs {
        std::thread::sleep(std::time::Duration::from_secs(s));
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
    Outcome { id: c.id, category: c.category, severity: c.severity, violation, control_broke, infra_error: false, passed, detail }
}
