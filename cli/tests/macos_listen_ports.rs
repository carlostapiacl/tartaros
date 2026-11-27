//! `--listen N` lets the agent serve on N; `--port N` only lets it connect.
//!
//! A test suite that starts its own server needs to bind and listen. That is an
//! inbound channel, so it is its own opt-in: a port grant stays connect-only,
//! and any other port and port 0 (ephemeral) stay denied.
//!
//! The child is this same test binary, run under tartaros by the parent test.
#![cfg(target_os = "macos")]

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_tartaros");
const PORT: &str = "TARTAROS_TEST_PORT";
const OTHER: &str = "TARTAROS_TEST_OTHER_PORT";
const CHILDREN: [&str; 2] = ["child_serves_the_granted_port", "child_cannot_bind_other_ports"];
const PORT_ONLY_CHILD: &str = "child_cannot_listen_on_a_connect_grant";

fn port(var: &str) -> u16 {
    std::env::var(var).unwrap().parse().unwrap()
}

/// A port that is free right now, found outside the sandbox.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

#[test]
#[ignore = "the child of a_granted_port_can_be_served"]
fn child_serves_the_granted_port() {
    let p = port(PORT);
    let server = TcpListener::bind(("127.0.0.1", p)).expect("bind the granted port");
    let mut client = TcpStream::connect(("127.0.0.1", p)).expect("connect to it");
    let (mut conn, _) = server.accept().expect("accept");
    client.write_all(b"ok").unwrap();
    let mut buf = [0u8; 2];
    conn.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"ok");
}

#[test]
#[ignore = "the child of a_granted_port_can_be_served"]
fn child_cannot_bind_other_ports() {
    for p in [port(OTHER), 0] {
        let err = TcpListener::bind(("127.0.0.1", p)).expect_err(&format!("bind 127.0.0.1:{p} must be refused"));
        assert_eq!(err.kind(), ErrorKind::PermissionDenied, "bind 127.0.0.1:{p}: {err}");
    }
}

#[test]
#[ignore = "the child of a_connect_grant_cannot_be_served"]
fn child_cannot_listen_on_a_connect_grant() {
    let p = port(PORT);
    let err = TcpListener::bind(("127.0.0.1", p)).expect_err("--port must not let the agent listen");
    assert_eq!(err.kind(), ErrorKind::PermissionDenied, "bind 127.0.0.1:{p}: {err}");
}

#[test]
fn a_connect_grant_cannot_be_served() {
    let dir = std::env::temp_dir().join(format!("tartaros-port-connect-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let granted = free_port();
    let me = std::env::current_exe().unwrap();
    let out = Command::new(BIN)
        .arg("run").arg("--write").arg(&dir)
        .arg("--port").arg(granted.to_string())
        .arg("--env").arg(format!("{PORT}={granted}"))
        .arg("--").arg(&me)
        .args(["--ignored", "--exact", PORT_ONLY_CHILD, "--nocapture"])
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(dir);
    assert!(out.status.success(), "{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
}

#[test]
fn a_granted_port_can_be_served() {
    let dir = std::env::temp_dir().join(format!("tartaros-listen-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (granted, other) = (free_port(), free_port());

    let me = std::env::current_exe().unwrap();
    let mut failures = Vec::new();
    for child in CHILDREN {
        let out = Command::new(BIN)
            .arg("run").arg("--write").arg(&dir)
            .arg("--listen").arg(granted.to_string())
            .arg("--env").arg(format!("{PORT}={granted}"))
            .arg("--env").arg(format!("{OTHER}={other}"))
            .arg("--").arg(&me)
            .args(["--ignored", "--exact", child, "--nocapture"])
            .output()
            .unwrap();
        if !out.status.success() {
            failures.push(format!(
                "{child}: {}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ));
        }
    }
    let _ = std::fs::remove_dir_all(dir);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
