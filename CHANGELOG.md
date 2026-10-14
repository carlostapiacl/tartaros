# Changelog

All notable changes to TartarOS. This project is pre-1.0; the format is
loosely [Keep a Changelog](https://keepachangelog.com/).

## [0.1.0-alpha] — 2026-10-13

First consolidated alpha: the open enforcement layer (policy model + macOS
Seatbelt and Linux Landlock backends) with its differentiator, a session
supervisor, resource confinement, a conformance suite, and low launch overhead.
Verified on a Linux host (kernel 6.8) and macOS 15.7.

### Filesystem & trust-handoff (the differentiator)
- Path-based protection of the **trust-handoff set at any depth**: nested
  `.git/hooks` and `.git/config`, `.mcp.json`, `.claude/{settings,commands,
  agents,skills}`, `.vscode/{tasks,launch}.json`, `.gitattributes`,
  `.gitmodules`, `.envrc`, `.pre-commit-config.yaml`, `.github/workflows`.
- `.codex` (Codex CLI config) added to the handoff set; macOS expresses the
  whole set as any-depth regex rules (no filesystem walk at compile time).
- **Handoff set completed (adversarial review #2)**: added `.claude/hooks`,
  `.husky/` (git `core.hooksPath`), and `.vscode/settings.json`; **submodule
  gitdirs** (`.git/modules/<name>/{hooks,config}` at any nesting, objects/refs left
  writable); and the **`.git` pointer file** of a worktree/submodule (rewriting it
  repoints the repo at attacker hooks) — denied on Linux (the walk denies the
  existing file) and, on macOS, hooks/config under `.git/modules` via regex.
  Regression `trust-handoff-submodule-hook`; verified on both OS.
- **Deny-inside-allow** on Linux via a carved Landlock allow-list (a policy
  nono cannot express). Ancestor-rename and symlink-escape safe.
- `read_denies` carves secret dirs out of the read grant; **`read_allows`**
  re-open a branch inside a deny, with **specificity precedence** (the deepest
  rule wins, so a deny nested inside a re-allow is not re-opened). On an EXACT tie
  (the same path both denied and re-allowed) the **deny wins, fail-safe** (F-4),
  on both OS — a tie never resolves to the permissive rule. Regression
  `read-deny-wins-exact-tie`.
- **Create new entries at a writable repo root** on Linux via read-only **bind
  mounts** of the handoff set (root or an unprivileged user namespace), instead
  of the carve — which cannot grant creation at a root with a deny below. Touches
  only existing paths (no working-tree residue); `.git` bound as one mount. Falls
  back to the carve + an `explain` warning where no mount namespace is available.

### Network
- Default-deny; per-port loopback TCP via Landlock (ABI v4+).
- **`--allow-domain HOST`**: egress scoped to named domains through the broker as
  a CONNECT/forward proxy (HTTPS tunneled end-to-end, SSRF-defended); the agent
  gets no other egress and a proxy-bypassing direct dial is blocked by the
  sandbox. Mutually exclusive with `--net` / `--isolate-net`.
- **CONNECT port mediation (ADV-03)**: a CONNECT tunnel is permitted only on an
  allowed destination port (domain-scoped egress uses **443**), so an allow-listed
  host cannot be reached as a raw TCP endpoint on an arbitrary port. Stated
  honestly: this is a host:port capability — TLS is end-to-end, the broker does
  not inspect SNI or the certificate. Regression test
  `live_connect_refuses_non_https_port`.
- **Default-deny closes ALL protocols, not just TCP (F-1)**: Landlock mediates
  TCP connect/bind only, so a network-restricted policy (default-deny, or
  `--allow-domain` which scopes TCP through the broker) used to leave UDP (DNS,
  QUIC/HTTP3), ICMP, raw sockets and IPv6 datagrams open — a working exfil
  side-channel around the broker. A seccomp filter now denies
  `socket(AF_INET|AF_INET6, SOCK_DGRAM|SOCK_RAW)` whenever the network is
  restricted; TCP (to the broker / granted ports) and `AF_UNIX` are untouched, and
  `--net` (opt-in full egress) leaves UDP available. Reproduced and closed on a Linux host
  (UDP/DNS, ICMP, IPv6-UDP all `EPERM`; broker HTTPS still 200). Regression
  `egress-udp-raw-denied`; needs no namespace (unlike `--isolate-net`).
- **`--isolate-net`**: empty network namespace (loopback only) — belt-and-suspenders
  over the seccomp close, blocking egress at the routing layer too (NET-1).
- Per-path **AF_UNIX allow** on macOS (`allowUnixSockets`); Linux is
  all-or-nothing (`--deny-unix`) and says so.

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
- **Secret never printed; token compared in constant time (review)**: `Injection`
  has a manual `Debug` that redacts its value (a derived `Debug` would print the
  injected secret if a broker/capability were ever logged), and the client-auth
  token is checked with a constant-time comparison instead of `==`.
- **Availability under abuse (ADV-01)**: the broker runs in the trusted supervisor
  and the agent is adversarial, so one client must never block another. Each
  connection is handled on its own bounded worker thread (`MAX_CONCURRENT_SESSIONS`,
  503 beyond it), every client read/write is time-bounded (`CLIENT_IO_TIMEOUT`),
  and a CONNECT tunnel has an idle read timeout (`CONNECT_IDLE_TIMEOUT`) — so a
  slowloris, held-open, or idle client can no longer pin the broker or starve
  others. Workers emit events over a channel drained by a single sink owner.
  Regression test: `live_slow_client_does_not_block_others`.

### Resource limits & lifecycle (root-proof on Linux)
- Processes via cgroup v2 **`pids.max`** (kernel-enforced, not RLIMIT — holds
  even as root); memory via `memory.max` + `RLIMIT_AS`; CPU via `RLIMIT_CPU`.
- Reliable teardown via **`cgroup.kill`**: reaps even a daemon that
  double-forked and `setsid`'d out of the process group.
- **Open-fd ceiling bounded**: the inherited soft `RLIMIT_NOFILE` (often 1024) is
  raisable by the agent up to the hard limit (often ~1M), letting it exhaust kernel
  fd-table memory. The hard limit is now capped at 65536 (generous for real
  toolchains, un-raisable past it). Disk space is still not quota'd — see Honest
  limits.
- **Kill-switch** (`PR_SET_PDEATHSIG`): the agent dies with its supervisor;
  with `--isolate-pids` the whole PID-namespace tree collapses.
- **Strict caps are guaranteed-or-abort, with a precise cause (ADV-04)**: in
  `--strict` a requested cap that a partially-delegated cgroup cannot install
  (`pids.max`/`memory.max` write refused, or cgroup membership that does not take
  effect) now aborts naming the exact failure, instead of a generic "no cgroup"
  message or a silent degrade. Non-strict degradation to RLIMIT is warned for
  **every** affected cap (`--max-procs` and `--max-mem`), not just processes.

### Root-agent hardening (adversarial review #3)
- **No device-node creation**: the Landlock write grant drops `MakeBlock`/
  `MakeChar`, and `mknod`/`mknodat` are denied via seccomp — a root agent can no
  longer `mknod` a block device and read the raw disk to bypass path-based secret
  protection.
- **All capabilities dropped before exec** when running as real root: the bounding
  set is emptied, `SECBIT_NOROOT` is set+locked, and the effective/permitted/
  inheritable sets are zeroed, so the agent loses CAP_SYS_MODULE, CAP_SYS_RAWIO,
  CAP_SYS_PTRACE, CAP_SYS_ADMIN, CAP_MKNOD, CAP_NET_RAW, … (verified: the agent's
  `CapEff` is `0000000000000000`). No-op for a non-root euid / inside a userns.
  Regression `root-mknod-device-denied`.

### Process isolation & kernel attack surface
- **`--isolate-pids`**: private PID + mount namespace — the agent sees only its
  own subtree, cannot enumerate/inspect/signal host processes.
- **Unprivileged isolation.** `--isolate-pids`/`--isolate-net` and the
  create-at-root bind mounts now enter a user namespace first for a non-root
  caller (bubblewrap's approach), so they work without root wherever the host
  permits unprivileged user namespaces. The userns is entered once and shared, so
  isolation and bind mounts compose. Verified on a hardened Ubuntu host (kernel
  6.8) as a non-root user.
- **`--seccomp-strict`**: deny dangerous syscalls (module load, kexec, keyring,
  bpf, perf, ptrace, process_vm_*, mount/unshare/setns, reboot/time/swap).
- Opt-in `--deny-unix` (AF_UNIX via seccomp).
- **io_uring denied when any socket filter is active (review #4)**: `IORING_OP_SOCKET`/
  `IORING_OP_CONNECT` create and connect sockets WITHOUT the `socket()`/`connect()`
  syscalls, bypassing `deny_af_unix` and the F-1 UDP/raw deny. `io_uring_setup`/
  `enter`/`register` are now denied whenever a socket filter runs, so the bypass is
  closed; libraries that probe io_uring fall back.
- **Host-socket reachability is never silent (F-3)**: Linux has no per-path AF_UNIX
  filtering (Landlock does not govern `connect()` to a pathname socket; seccomp is
  all-or-nothing), so a confined agent can reach `docker.sock`, containerd, D-Bus
  or systemd — a host-escape vector — unless AF_UNIX is denied. The `hostile-code`
  / `multi-tenant` profiles and `--deny-unix` block it; the default now **warns at
  launch** when such a socket is present (reproduced on a Linux host: a default run reached
  `docker.sock` and the D-Bus bus; the hardened profiles close it).

### Effect log (observability)
- Collectors observe the process tree and emit `EffectEvent`s on five axes —
  network, secret, process, MCP and **file-write** — on both OS. `RecordMode`
  (Off / DeniedOnly / OutsideOnly / Boundary / All) + an axis filter choose how
  much is recorded; `--log` writes JSON Lines.
- **`FileCollector`** (new) watches write-mode file descriptors across the tree
  (Linux `/proc/<pid>/fdinfo` flags, macOS `lsof -F fan`) and classifies each
  within / outside the writable roots — the file axis now has a collector, so the
  log covers all five axes. Honest scope: it observes *allowed* writes; a denied
  write is blocked by enforcement before the fd opens (enforced, not logged). The
  log is a sampled observation feed for visibility and intent (the intent layer), never the
  enforcement boundary.

### Threat-model profiles
- `--profile local-agent | hostile-code | multi-tenant`, applied before flags,
  each with an honest caveat printed on run and in `explain`. `multi-tenant`
  states plainly it does **not** provide kernel isolation.

### Post-fork safety (adversarial review #7)
- **No allocation in `pre_exec`.** Building a seccomp BPF program, or any
  `format!`, after `fork()` in a child of a multithreaded parent (the broker and
  effect-log collectors run on their own threads) can deadlock on the glibc malloc
  lock — the agent then never execs and the supervisor's timeout never starts. The
  child's `pre_exec` now only makes async-signal-safe syscalls: the seccomp filters
  are **compiled in the parent** (`seccomp::compile_all`) and merely applied in the
  child (`apply_all` = `prctl` + `apply_filter`); the cgroup pid is written with a
  stack buffer (`fmt_pid`, no `format!`); and the user-namespace uid/gid maps are
  pre-built in the parent (`uid_gid_maps`). Verified: seccomp still denies UDP/
  AF_UNIX/io_uring, caps still drop, bench 28/28.

### Honesty / fail-closed
- Fail-closed capability probes (Landlock fs/net; a cgroup membership probe).
- macOS refuses Linux-only hardening instead of silently ignoring it.
- A cgroup-less host warns that `--max-procs` degraded to RLIMIT.
- **Config typos fail closed, not open (review)**: the `--config` TOML and
  `--settings` JSON structs use `deny_unknown_fields`, so a mistyped key (e.g.
  `read_deny` for `read_denies`) is a hard parse error (exit 2) instead of being
  silently dropped and leaving a secret readable.
- **Numeric flags reject non-numbers (review)**: `--timeout`/`--max-mem`/
  `--max-procs`/`--max-cpu` error on an unparseable value instead of silently
  becoming 0 — so `--timeout 10m` no longer means "no timeout".
- **Namespace unavailable → named diagnostic, never a silent downgrade.** Where a
  host forbids unprivileged user namespaces (hardened Ubuntu
  `apparmor_restrict_unprivileged_userns=1`, Debian/Arch `unprivileged_userns_clone=0`,
  `max_user_namespaces=0`, or a CAP_SYS_ADMIN-less container), `--isolate-pids`/
  `--isolate-net` refuse with a message naming the exact blocking knob and its
  remedy; the create-at-root bind mounts fall back to the Landlock carve + an
  `explain` warning. The base sandbox needs no namespace and still runs.
- **`explain` matches `run`'s verdict.** `explain` now exits non-zero (2) wherever
  `run` would refuse on this host — no Landlock, Landlock net unavailable when a
  denial is required, isolation requested without a grantable namespace, or strict
  caps with no usable cgroup — so an audit (an external `check`) never shows a green ✓
  on a host that cannot actually enforce the policy.

### sandbox-runtime compatibility
- **`--settings <file>`**: maps a sandbox-runtime `settings.json`
  (filesystem/network allow-deny) onto the policy, applying every field it can
  enforce and **refusing** (exit 2) anything it cannot — apply-fully-or-refuse.
- Pattern handling: single-character classes (`.vscod[e]`) unwrap to the literal
  path; any-depth globs covered by the handoff set map to it; single-`*` globs
  compile to anchored Seatbelt regexes on macOS (refused on Linux); arbitrary
  globs are refused rather than treated as never-matching literals.
- **`--browser` — headless Chromium/Chrome Seatbelt grants (macOS)**: the minimal
  extra rules a headless browser needs, measured against Playwright + the headless
  shell (measured against a headless browser): POSIX shared memory for `apple.cfprefs.*` and
  `apple.shm.notification_center`, POSIX semaphores, the IOSurface/RootDomain IOKit
  user clients + `iokit-get-properties`, and `sysctl-read kern.proc.pid.` /
  `sysctl-write kern.tcsm_enable`. Scoped and opt-in — never a blanket open — and
  the `kern.proc.pid.` read is emitted after the env-leak deny so the browser's own
  process info is readable while other processes stay denied. Linux refuses
  `--browser` (macOS concept). Without these headless Chromium SIGSEGVs at startup.
- **Ancestor metadata under a carved read grant (macOS)**: when a read-deny covers
  an ancestor of the territory (e.g. `/private/tmp` above the repo), the ancestor
  directory NODES are now `file-read-metadata`-readable, so a tool can `lstat`/
  `stat` them to reach the paths it is allowed (Node failed with
  `EPERM lstat('/private/tmp')` before) — contents stay denied. Matches
  sandbox-runtime.
- **Headless-browser Mach rendezvous (macOS)**: `--settings` maps
  `network.allowMachLookup` and the new `allowMachRegister` (sandbox-runtime's
  `*`-suffix = name prefix) onto scoped Seatbelt `(allow mach-register
  (global-name-prefix …))` rules — never a blanket `(allow mach-register)`.
  Chromium/Chrome headless register a `MachPortRendezvousServer.*` service their
  child processes look up; without register the browser dies at startup. Mach is a
  Darwin primitive, so the Linux backend refuses these fields (apply-or-refuse).
- **`--private-tmp` for headless browsers**: creates a run-private temp dir,
  exports it as `TMPDIR`, makes it writable, and (macOS) scopes AF_UNIX bind/connect
  to it — `(allow network-bind/outbound (… unix-socket (subpath …)))`. Playwright
  publishes its browser control socket under `$TMPDIR`, so it lands in the
  run-private dir instead of the shared temp where other runs' sockets live; no
  Playwright internals are needed (only `TMPDIR` is set). Torn down after the run.
  Verified on Linux and macOS (a socket inside the dir works; binding outside is
  denied on macOS).
- **Attributable denials on macOS**: every deny carries `(with message
  "CMD64_…_SBX")` so a kernel denial is traceable in the unified log even after
  the process exits (matches sandbox-runtime's `generateLogTag`/`renderRule`).
- **Differential corpus for apply-fully-or-refuse (ADV-08)**: `cli/tests/
  settings_corpus.rs` drives the real binary with `explain --settings` over valid
  and invalid patterns (literals, single-char classes, any-depth covered/uncovered
  by the handoff set, globs in allow rules, per-domain deny, and a single-`*` glob)
  and asserts each is applied (exit 0) or refused (exit 2) — never silently
  widened. The single-`*` case is OS-differential (macOS regex applies, Linux
  refuses) and the test asserts both are non-permissive. 9/9 on Linux and macOS.

### Conformance (`tartaros-bench`)
- 28-scenario corpus; PASS / VIOLATION / CONTROL_BROKE / INFRA_ERROR / SKIPPED /
  **UNSUPPORTED**; exits non-zero on any failure.
- **Coverage gate (ADV-05)**: the scorecard prints `coverage: ran/applicable` and
  the JSON carries the host capability stamp + skipped/unsupported counts, so a
  green exit is never misread as a full certification. `--require-caps
  landlock,cgroup,userns` makes a release run FAIL on a host missing any demanded
  capability, instead of passing with scenarios silently UNSUPPORTED.
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
