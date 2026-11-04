//! A terminal's Ctrl-C reaches the agent, and only the agent decides what it
//! means. The run has a process group of its own, so before 0.1.0-alpha.20 a
//! SIGINT to the launcher's group killed the launcher and the run with it, even
//! an agent that catches SIGINT to interrupt rather than quit (Claude Code does).
#![cfg(unix)]

use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::io::{BufRead, BufReader};

const BIN: &str = env!("CARGO_BIN_EXE_tartaros");

#[test]
fn a_sigint_to_the_launchers_group_reaches_an_agent_that_catches_it() {
    let dir = std::env::temp_dir().join(format!("tartaros-signals-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let script = "n=0; trap 'n=$((n+1))' INT; echo ready; i=0; while [ $i -lt 20 ]; do sleep 0.1; i=$((i+1)); done; echo got $n";
    let mut child = Command::new(BIN)
        .arg("run").arg("--write").arg(&dir).args(["--", "sh", "-c", script])
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    out.read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "ready");
    // As a terminal does: the signal goes to the foreground group, the launcher's.
    let pgid = format!("-{}", child.id());
    assert!(Command::new("kill").args(["-INT", "--", &pgid]).status().unwrap().success());
    line.clear();
    out.read_line(&mut line).unwrap();
    let status = child.wait().unwrap();
    assert_eq!(line.trim(), "got 1", "the agent did not see the Ctrl-C");
    assert_eq!(status.code(), Some(0), "the run ended by the signal: {status:?}");
    let _ = std::fs::remove_dir_all(dir);
}
