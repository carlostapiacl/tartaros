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

**Fix plan (closure):** run the agent in a network namespace that has loopback
only and no external route, with the broker bridged in (bound inside that netns, or
reachable via a veth with no default route). Then a connect to any external IP:port
fails at the network layer regardless of Landlock. Needs CAP_SYS_ADMIN/userns
(same privilege tier as the bind-mount handoff strategy); falls back to the warning
when unavailable. Not a pure-corpus scenario (needs a live external listener), so it
is tracked here rather than as a runnable `.toml`.
