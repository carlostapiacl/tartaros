//! A run's secrets never sit in an exec-time environment the agent can read.
//!
//! A process's exec environment can stay readable for its life by other
//! processes of the same user (`/proc/<pid>/environ` on Linux). tartaros reads masked credentials and
//! `[broker]` secrets from its environment, so before the broker or the agent
//! exist it re-execs itself without them (`reexec_without_secrets`). This runs a
//! real `tartaros run` whose agent scans every process it can read for the
//! secret, and asserts it finds none — the launcher here is this test process,
//! which passes the secret only into tartaros's environment, not its own. The
//! scan is Linux's `/proc`; elsewhere the test checks what the agent holds.

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_tartaros");
const SECRET: &str = "ghp_REALSECRET_tartaros_test_7f3a";

/// The scanner: prints the agent's own GH_TOKEN, then `HIT <pid>` for every
/// process whose readable exec record holds the secret, then `DONE`.
const PROBE: &str = r#"
import os, sys
secret = bytes.fromhex(sys.argv[1])  # hex on argv: the secret itself is on no command line
print("AGENT_SEES", os.environ.get("GH_TOKEN", ""))
print("FD_VAR", os.environ.get("TARTAROS_INTERNAL_SECRETS_FD", "none"))
hits = []
def rec(pid):
    try:
        with open(f"/proc/{pid}/environ", "rb") as f:
            return f.read()
    except OSError:
        return None
pids = [int(p) for p in os.listdir("/proc") if p.isdigit()] if os.path.isdir("/proc") else []
readable = 0
for pid in pids:
    d = rec(pid)
    if d is None:
        continue
    readable += 1
    if secret in d:
        hits.append(pid)
print("READABLE", readable)
for h in hits:
    print("HIT", h)
print("DONE")
"#;

fn python() -> Option<&'static str> {
    ["/usr/bin/python3", "/usr/local/bin/python3", "/opt/homebrew/bin/python3"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
}

fn scratch(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("tartaros-secrets-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Run the probe under `tartaros run <args>` with `var` (holding the secret) in
/// tartaros's environment only; return its stdout.
fn probe(dir: &std::path::Path, args: &[&str], var: (&str, String)) -> String {
    let py = python().expect("python3");
    std::fs::write(dir.join("probe.py"), PROBE).unwrap();
    let out = Command::new(BIN)
        .arg("run")
        .args(args)
        .args(["--", py, "-I"])
        .arg(dir.join("probe.py"))
        .arg(SECRET.bytes().map(|b| format!("{b:02x}")).collect::<String>())
        .env_remove("GH_TOKEN")
        .env_remove("GH_AUTH")
        .env(var.0, var.1)
        .output()
        .expect("run tartaros");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(stdout.contains("DONE"), "the probe did not finish: {stdout}\nstderr: {}", String::from_utf8_lossy(&out.stderr));
    stdout
}

fn assert_clean(out: &str) {
    let hits: Vec<&str> = out.lines().filter(|l| l.starts_with("HIT ")).collect();
    assert!(hits.is_empty(), "the secret is readable in these processes' exec records: {hits:?}\n{out}");
    assert!(out.contains("FD_VAR none"), "the pipe's fd variable reached the agent: {out}");
    let readable: usize = out.lines().find_map(|l| l.strip_prefix("READABLE ")).and_then(|n| n.parse().ok()).unwrap_or(0);
    if cfg!(target_os = "linux") {
        assert!(readable > 0, "the probe could read no process at all, so it proves nothing: {out}");
    }
}

#[test]
fn masked_credentials_are_not_in_any_readable_exec_environment() {
    if python().is_none() {
        eprintln!("skipped: no python3");
        return;
    }
    let dir = scratch("mask");
    let settings = dir.join("settings.json");
    std::fs::write(
        &settings,
        format!(
            r#"{{"filesystem":{{"allowWrite":["{}"]}},"network":{{"allowedDomains":["api.github.com"],"tlsTerminate":{{"excludeDomains":[]}}}},"credentials":{{"envVars":[{{"name":"GH_TOKEN","mode":"mask","injectHosts":["api.github.com"]}}]}}}}"#,
            dir.display()
        ),
    )
    .unwrap();
    // --inherit-env: the case where the whole launcher environment is passed on.
    let out = probe(&dir, &["--inherit-env", "--settings", settings.to_str().unwrap()], ("GH_TOKEN", SECRET.to_string()));
    assert_clean(&out);
    assert!(out.contains("AGENT_SEES fake_value_"), "the agent's GH_TOKEN must be the sentinel: {out}");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn broker_value_env_secrets_are_not_in_any_readable_exec_environment() {
    if python().is_none() {
        eprintln!("skipped: no python3");
        return;
    }
    let dir = scratch("broker");
    let cfg = dir.join("policy.toml");
    std::fs::write(
        &cfg,
        format!(
            "writable_roots = [\"{}\"]\n\n[broker]\n\n[[broker.capability]]\nprefix = \"/gh\"\nupstream = \"https://api.github.com\"\n[[broker.capability.inject]]\nheader = \"Authorization\"\nvalue_env = \"GH_AUTH\"\n",
            dir.display()
        ),
    )
    .unwrap();
    let out = probe(&dir, &["--inherit-env", "--config", cfg.to_str().unwrap()], ("GH_AUTH", format!("Bearer {SECRET}")));
    assert_clean(&out);
    assert!(!out.contains(SECRET.split('_').last().unwrap()) || !out.contains("HIT"), "{out}");
    let _ = std::fs::remove_dir_all(dir);
}

/// Another process that holds a run's secret in its exec record (a shell's
/// `export` hands it to every child) refuses the run: the agent could read it
/// there. `--allow-exposed-secrets` runs anyway.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn a_secret_another_process_exposes_refuses_the_run() {
    // Its own value: the other tests' tartaros hold theirs for an instant before the re-exec.
    const EXPOSED: &str = "ghp_EXPOSED_tartaros_test_4c1d";
    let dir = scratch("exposed");
    // The holder. macOS hides the environment of Apple's own binaries (`/bin/sleep`), not of others: tartaros
    // without secrets to clean keeps it.
    let mut holder = if cfg!(target_os = "macos") {
        Command::new(BIN).args(["run", "--write", dir.to_str().unwrap(), "--", "/bin/sleep", "30"]).env("GH_TOKEN", EXPOSED).spawn()
    } else {
        Command::new("/bin/sleep").arg("30").env("GH_TOKEN", EXPOSED).spawn()
    }
    .expect("spawn the holder");
    std::thread::sleep(std::time::Duration::from_millis(300));
    let settings = dir.join("settings.json");
    std::fs::write(
        &settings,
        format!(
            r#"{{"filesystem":{{"allowWrite":["{}"]}},"network":{{"allowedDomains":["api.github.com"],"tlsTerminate":{{"excludeDomains":[]}}}},"credentials":{{"envVars":[{{"name":"GH_TOKEN","mode":"mask","injectHosts":["api.github.com"]}}]}}}}"#,
            dir.display()
        ),
    )
    .unwrap();
    let run = |extra: &[&str]| {
        Command::new(BIN)
            .args(["run", "--settings", settings.to_str().unwrap()])
            .args(extra)
            .args(["--", "/usr/bin/true"])
            .env("GH_TOKEN", EXPOSED)
            .output()
            .expect("run tartaros")
    };
    let refused = run(&[]);
    let err = String::from_utf8_lossy(&refused.stderr);
    let allowed = run(&["--allow-exposed-secrets"]);
    let _ = holder.kill();
    let _ = holder.wait();
    assert_eq!(refused.status.code(), Some(78), "{err}");
    assert!(err.contains(&format!("GH_TOKEN in pid {}", holder.id())), "{err}");
    assert!(!err.contains(EXPOSED), "the refusal must not print the value: {err}");
    assert!(allowed.status.success(), "{}", String::from_utf8_lossy(&allowed.stderr));
    let _ = std::fs::remove_dir_all(dir);
}
