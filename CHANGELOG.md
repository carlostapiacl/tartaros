# Changelog

All notable changes to TartarOS. This project is pre-1.0; the format is
loosely [Keep a Changelog](https://keepachangelog.com/).

## [0.1.0-alpha] — 2026-10-13

First consolidated alpha: the open enforcement layer (policy model + macOS
Seatbelt and Linux Landlock backends) with its differentiator, a session
supervisor, resource confinement, a conformance suite, and low launch overhead.
Verified on the Linux test host (Linux 6.8) and macOS 15.7.

### Filesystem & trust-handoff (the differentiator)
- Path-based protection of the **trust-handoff set at any depth**: nested
  `.git/hooks` and `.git/config`, `.mcp.json`, `.claude/{settings,commands,
  agents,skills}`, `.vscode/{tasks,launch}.json`, `.gitattributes`,
  `.gitmodules`, `.envrc`, `.pre-commit-config.yaml`, `.github/workflows`.
- **Deny-inside-allow** on Linux via a carved Landlock allow-list (a policy
  nono cannot express). Ancestor-rename and symlink-escape safe.
- `read_denies` carves secret dirs out of the read grant.

### Network
- Default-deny; per-port loopback TCP via Landlock (ABI v4+).
- **`--isolate-net`**: empty network namespace (loopback only) — closes TCP,
  UDP, ICMP and raw, not just TCP (NET-1).

### Capability gateway / supervisor (broker)
- Mandatory client auth (`X-Tartaros-Auth`); capability endpoints by prefix and
  method (405 for undeclared); bounded response.
- **TTL** (`with_ttl`) and **request quota** (`with_quota`).
- **Host egress allow-list** with subdomain wildcards and look-alike rejection.
- **SSRF / internal-destination defense**: resolves the host, refuses internal
  IPs (loopback, RFC1918, 169.254 metadata, ULA, CGNAT), connects to the
  resolved address (no rebinding window).
- **Bounded request parsing** (per-line and header-count caps) so a confined
  agent cannot OOM the supervisor.

### Resource limits & lifecycle (root-proof on Linux)
- Processes via cgroup v2 **`pids.max`** (kernel-enforced, not RLIMIT — holds
  even as root); memory via `memory.max` + `RLIMIT_AS`; CPU via `RLIMIT_CPU`.
- Reliable teardown via **`cgroup.kill`**: reaps even a daemon that
  double-forked and `setsid`'d out of the process group.
- **Kill-switch** (`PR_SET_PDEATHSIG`): the agent dies with its supervisor;
  with `--isolate-pids` the whole PID-namespace tree collapses.

### Process isolation & kernel attack surface
- **`--isolate-pids`**: private PID + mount namespace — the agent sees only its
  own subtree, cannot enumerate/inspect/signal host processes.
- **`--seccomp-strict`**: deny dangerous syscalls (module load, kexec, keyring,
  bpf, perf, ptrace, process_vm_*, mount/unshare/setns, reboot/time/swap).
- Opt-in `--deny-unix` (AF_UNIX via seccomp).

### Threat-model profiles
- `--profile local-agent | hostile-code | multi-tenant`, applied before flags,
  each with an honest caveat printed on run and in `explain`. `multi-tenant`
  states plainly it does **not** provide kernel isolation.

### Honesty / fail-closed
- Fail-closed capability probes (Landlock fs/net; a cgroup membership probe).
- macOS refuses Linux-only hardening instead of silently ignoring it.
- A cgroup-less host warns that `--max-procs` degraded to RLIMIT.

### Conformance (`tartaros-bench`)
- 21-scenario corpus; PASS / VIOLATION / CONTROL_BROKE / INFRA_ERROR / SKIPPED /
  **UNSUPPORTED**; exits non-zero on any failure.
- **Mutation testing** (`--mutate`): removing a protection must flip ≥1 scenario.
- Self-describing **environment + host-capability stamp** in the report.
- **`--perf`** startup-overhead benchmark.
- Randomized **fuzz** property-test of the policy compiler (safety +
  monotonicity over random trees).

### CLI & distribution
- `run`, `explain`, `version`, `help`; TOML `--config`.
- Builds as a fully **static musl binary** (no glibc) for distroless / minimal
  containers.

### Performance
- Per-launch overhead p50 ≈ **+5.6 ms** (minimal policy) / **+8.8 ms** (hardened
  tier) over an unsandboxed launch (adaptive supervisor poll).
