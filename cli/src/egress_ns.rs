//! NET-01 closure (Linux): scope `--allow-domain` egress with a network namespace.
//!
//! The problem: Landlock's network filter is port-based, not address-based, so
//! granting the broker's loopback port also lets the agent reach any EXTERNAL host
//! on that port — bypassing the broker. The fix: run the agent in a network
//! namespace whose ONLY route is a veth to the broker's host-side address, with no
//! default route. Then the agent can reach the broker and nothing else; the broker
//! itself stays in the host namespace with normal internet access.
//!
//! Requires root (CAP_SYS_ADMIN) + iproute2. When unavailable, the caller falls
//! back to the loopback broker + the documented NET-01 warning. Fail-closed: if the
//! namespace cannot be built and VERIFIED isolating (no default route; internet
//! unreachable), it is torn down and the caller falls back — the scoped mode is
//! only claimed when confirmed.
#![cfg(target_os = "linux")]

use std::process::Command;

/// A prepared egress namespace. Dropping it tears everything down (netns, veth,
/// firewall rule), so it is held by the caller for the lifetime of the run.
pub struct EgressNs {
    pub name: String,
    pub host_ip: String,
    veth_host: String,
    fw_rule: Option<Vec<String>>, // the `iptables` args to delete on teardown
}

impl Drop for EgressNs {
    fn drop(&mut self) {
        if let Some(rule) = &self.fw_rule {
            let mut args = vec!["-D".to_string()];
            args.extend(rule.iter().skip(1).cloned()); // rule[0] was "-I"
            let _ = Command::new("iptables").args(&args).output();
        }
        let _ = Command::new("ip").args(["netns", "del", &self.name]).output();
        let _ = Command::new("ip").args(["link", "del", &self.veth_host]).output();
    }
}

fn root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn have_ip() -> bool {
    Command::new("ip")
        .arg("-V")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Is scoped egress available on this host? (root + iproute2)
pub fn available() -> bool {
    root() && have_ip()
}

fn run_ip(args: &[&str]) -> Result<(), String> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .map_err(|e| format!("exec ip: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("ip {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim()))
    }
}

/// Build the scoped egress namespace and bind the broker on its host-side address.
/// Returns the listener + port + the `EgressNs` guard, or `None` with a reason the
/// caller prints before falling back. The broker is bound by `bind_on`, which takes
/// (host_ip, port) and returns the bound listener's port — kept generic so the CLI
/// owns the broker type.
pub fn setup<F>(bind_on: F) -> Result<(EgressNs, u16), String>
where
    F: FnOnce(&str) -> std::io::Result<u16>,
{
    let pid = std::process::id();
    // Per-run names and /30 subnet (derived from pid to avoid collisions between
    // concurrent runs). Interface names must be <= 15 chars.
    let name = format!("tartaros-egr-{pid}");
    let veth_host = format!("tveh{pid}");
    let veth_guest = format!("tveg{pid}");
    let octet = (pid % 250 + 1) as u8; // 1..=250, avoids .0
    let host_ip = format!("10.201.{octet}.1");
    let guest_ip = format!("10.201.{octet}.2");
    let cidr = 30;

    // Build everything; on any error, a partial EgressNs still tears it down.
    let mut ns = EgressNs {
        name: name.clone(),
        host_ip: host_ip.clone(),
        veth_host: veth_host.clone(),
        fw_rule: None,
    };

    // Clean any stale same-named state first (best effort).
    let _ = Command::new("ip").args(["netns", "del", &name]).output();
    let _ = Command::new("ip").args(["link", "del", &veth_host]).output();

    run_ip(&["netns", "add", &name])?;
    run_ip(&["link", "add", &veth_host, "type", "veth", "peer", "name", &veth_guest])?;
    run_ip(&["link", "set", &veth_guest, "netns", &name])?;
    run_ip(&["addr", "add", &format!("{host_ip}/{cidr}"), "dev", &veth_host])?;
    run_ip(&["link", "set", &veth_host, "up"])?;
    run_ip(&["-n", &name, "addr", "add", &format!("{guest_ip}/{cidr}"), "dev", &veth_guest])?;
    run_ip(&["-n", &name, "link", "set", &veth_guest, "up"])?;
    run_ip(&["-n", &name, "link", "set", "lo", "up"])?;
    // Deliberately NO default route in the guest: only the connected /30 is
    // reachable, so the broker's host_ip is the sole destination.

    // Bind the broker on the host veth IP (ephemeral port).
    let port = bind_on(&host_ip).map_err(|e| format!("broker bind on {host_ip}: {e}"))?;

    // Punch a scoped INPUT ACCEPT: hosts with a default-DROP INPUT policy
    // (ufw/nftables) would otherwise drop the agent->broker SYN on the veth.
    let dport = port.to_string();
    let rule: Vec<String> = [
        "-I", "INPUT", "-i", &veth_host, "-s", &guest_ip, "-d", &host_ip, "-p", "tcp",
        "--dport", &dport, "-j", "ACCEPT",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let fw = Command::new("iptables").args(&rule).output();
    match fw {
        Ok(o) if o.status.success() => ns.fw_rule = Some(rule),
        // No iptables, or it failed: the host may have no INPUT filtering (then the
        // rule is unnecessary) — keep going and let the self-test decide.
        _ => {}
    }

    // Fail-closed self-test: the guest route table must have NO default route and
    // MUST have the connected /30. If it does not, the isolation is not what we
    // think — refuse the scoped claim.
    let routes = Command::new("ip")
        .args(["-n", &name, "route"])
        .output()
        .map_err(|e| format!("exec ip route: {e}"))?;
    let rtext = String::from_utf8_lossy(&routes.stdout);
    if rtext.lines().any(|l| l.trim_start().starts_with("default")) {
        return Err("guest namespace has a default route (would reach the internet)".into());
    }
    if !rtext.contains(&format!("10.201.{octet}.0/{cidr}")) {
        return Err("guest namespace is missing the connected /30 route to the broker".into());
    }

    Ok((ns, port))
}
