# Known gaps

Scenarios that currently FAIL on some backend. Kept out of `corpus/` (green =
verified) and tracked here with a fix plan.

Resolved: ipc-unix-socket via opt-in seccomp `deny_unix_sockets` (2026-10-13 —
moved back to `corpus/`).

## Open

### NET-01 — egress scope bypass via the broker's port (Linux, P0)

**Reproduced** on a Linux lab host (2026-10-14). `--allow-domain` starts the broker
on a loopback ephemeral port and grants it through Landlock
(`NetPort::new(port, ConnectTcp)`). Landlock's network filter is **port-based, not
address-based**, so the grant cannot be pinned to loopback: a direct TCP connection
to an *external* host on that same port succeeds, bypassing the broker's domain
scope and SSRF defense. A malicious agent learns the port from `HTTP_PROXY`.

Repro (confined agent, port 9999 granted, external server on 9999):
```
# server on 0.0.0.0:9999 (non-loopback)
tartaros run --write /tmp/x --port 9999 -- \
  python3 -c 'import socket,sys;s=socket.socket();s.settimeout(3);sys.exit(0 if s.connect_ex(("<host-ip>",9999))==0 else 1)'
# -> exit 0 (CONNECTS) = bypass
```

**Mitigated for now:** overclaims corrected (README/SECURITY/code), loud runtime
warning on `--allow-domain`, and documented as a non-guarantee —
`--allow-domain` is scoped egress for a *trusted-but-fallible* agent, not
hostile-code containment.

**Fix plan (closure) — DESIGN PROVEN on a Linux lab host (2026-10-14).** A
loopback-only netns does NOT work: the broker itself must reach the external
allowed domains, so it cannot live in a no-egress netns. The validated design is a
**veth pair**:

1. New netns for the agent; a `veth` pair with the host end (e.g. `10.200.0.1/30`)
   in the host netns and the peer (`10.200.0.2/30`) in the agent netns; `lo` up on
   both.
2. The agent netns gets **no default route** — only the connected `/30`. So it can
   reach exactly the broker's host-veth IP and nothing else.
3. The broker binds on the host-veth IP (`10.200.0.1:port`) and reaches the internet
   via the host's normal routing.
4. The agent is spawned into the netns; `HTTP(S)_PROXY=http://10.200.0.1:port`.

Verified: from the agent netns, `1.1.1.1:443` → blocked, the host's public IP on the
broker port (the NET-01 vector) → blocked, `ping 10.200.0.1` → works (L3 fine).
**Open implementation requirement found:** a host with a default-DROP INPUT policy
(ufw/firewalld/nftables) drops the agent→broker SYN on the veth interface, so the
implementation must also add a scoped INPUT ACCEPT (src `10.200.0.2` → dst
`10.200.0.1`:port on the veth iface) and remove it on teardown — and handle the
firewall variants. Needs root/CAP_SYS_ADMIN + iproute2; must be **fail-closed** (a
startup self-test confirms the agent can reach the broker but NOT the internet,
else refuse) and fall back to the documented warning when the privilege/tooling is
absent. Teardown removes the netns, veth and firewall rule. Not a pure-corpus
scenario (needs live external + a veth), so tracked here.
