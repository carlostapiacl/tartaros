# Limits, per OS

TartarOS states what it does **not** guarantee as precisely as what it does. Each
limit below is measured, and the ones with a fix in progress are on the
[roadmap](../ROADMAP.md). Where a host can't provide a protection you asked for,
TartarOS refuses to start or reports it `UNSUPPORTED`; it never runs you with less
than you asked for.


- **macOS teardown is best-effort.** A daemon that calls `setsid()` leaves the
  process group and `kill(-pgid)` misses it; macOS has no `cgroup.kill` or job
  object to match Linux's guarantee. Use Linux for strict teardown.
- **macOS cross-process environment read:** re-measured on macOS 15.7 (Darwin
  24.6) with a validated direct `KERN_PROCARGS2` probe — another same-user
  process's environment is **not** exposed (the OS returns only the executable
  path; a process reads the full environment only for itself). It does not
  reproduce on current macOS. A targeted `(deny sysctl-read (sysctl-name
  "kern.procargs2"))` remains available as defense-in-depth for older macOS.
- **Resource caps on a cgroup-less host degrade to RLIMIT** (bypassable by root)
  and TartarOS warns on stderr rather than pretending to confine.
- **Not-yet-existing handoff paths: macOS yes, Linux limited.** The real-world
  Trust-Handoff attack — poisoning a config/hook that *already exists* in the repo
  the agent works in — is blocked on both OS at any depth. Protecting a handoff
  path that does **not exist yet** (pre-planting: a new top-level
  `.claude/settings.json`, or a brand-new nested git repo's `.git/hooks`) is a
  macOS property (Seatbelt matches by regex, so absent paths are covered). On
  Linux it is inode-based: the carve + opt-in `--materialize` covers absent
  **top-level** configs (at the cost of placeholder residue), but under the
  whole-root-writable **bind-mount** strategy a not-yet-existing handoff path is
  not protected, and a newly-created nested repo's hooks are never auto-protected.
  `explain` states this for the active strategy. Measured, not hidden. The opt-in
  home-handoff surface (`--protect-home-handoff`: shell rc, `.gitconfig`,
  `.ripgreprc`) follows exactly this rule — top-level covered on both OS (Linux
  needs `--materialize` for the absent ones), nested-absent on Linux is the same
  bind-mount gap.
- **AF_UNIX pathname sockets are not path-filtered on Linux.** Landlock does not
  govern `connect()` to a unix socket by path, and the seccomp AF_UNIX deny is
  all-or-nothing, so a confined agent can reach a host daemon's socket
  (`docker.sock`, containerd, D-Bus, systemd) unless AF_UNIX is denied wholesale —
  a host-escape vector. `--deny-unix` and the `hostile-code` / `multi-tenant`
  profiles block it; the default (`local-agent`) does not, but **warns loudly** at
  launch when such a socket is present rather than leaving it silent. macOS filters
  AF_UNIX by path (`allowUnixSockets`) and denies it by default in the Seatbelt
  profile, so this is Linux-only. (Reproduced: a default run reached `docker.sock`
  and the D-Bus bus; `--deny-unix` / `hostile-code` close it.)
- **No disk-space quota.** `--max-mem` caps memory, not disk: an agent can fill a
  writable root (and the underlying filesystem) until it is full — a host DoS that
  path-based confinement does not stop. Open fds are bounded (hard `RLIMIT_NOFILE`
  capped at 65536) and processes by `pids.max`, but bytes-on-disk are not. For
  untrusted code, give the writable root its own size-limited mount (a `tmpfs` with
  `size=`, a loop device, or a filesystem project quota) — a disk-quota knob is not
  yet built ([roadmap](../ROADMAP.md)).
- **Running the agent as root is hardened, not a microVM.** A root agent now runs
  with **no capabilities** (bounding set emptied, `SECBIT_NOROOT`, cap sets zeroed)
  and cannot create device nodes (Landlock drops `MakeBlock`/`MakeChar`; seccomp
  denies `mknod`), so module load, raw I/O, host ptrace and raw-disk-via-`mknod`
  are closed. One residual: a uid-0 agent can still *read an already-existing*
  root-owned block device (e.g. `/dev/sda`) through owner permissions, which raw
  bytes bypass path rules — run the agent as a **non-root uid** (or don't expose
  block devices) for that case. A shared kernel is still a shared kernel; true
  tenant isolation is the job of the microVM backend (phase 1 validated under gVisor; phase 2 on the [roadmap](../ROADMAP.md)).
- **The effect log is observed, not a guarantee.** Enforcement is guaranteed; the
  log is fed by collectors that sample the process tree (network, secret, process,
  MCP and file-write, on both OS), so a very short-lived event can be missed. The
  file-write collector observes *allowed* writes — a denied write (outside the
  roots or to a handoff path) is blocked before the fd opens, so it is enforced,
  not logged. Use the log for visibility and intent, never as the enforcement
  boundary — that is the kernel policy.
- **Namespaces need root or an unprivileged user namespace on Linux.** The mount
  namespace (for the create-at-root bind mounts) and the PID/net namespaces
  (`--isolate-pids`/`--isolate-net`) require CAP_SYS_ADMIN; a non-root user gets it
  by entering a user namespace first (as bubblewrap does). Where a host forbids
  unprivileged user namespaces (hardened Ubuntu with
  `apparmor_restrict_unprivileged_userns=1`, Debian/Arch with
  `unprivileged_userns_clone=0`, or a container without CAP_SYS_ADMIN) the two
  behaviours differ **by design, never silently**:
  - `--isolate-pids`/`--isolate-net` **refuse to start** with a one-line diagnostic
    that names the exact blocking knob and its remedy — fail-closed, because the
    caller asked for isolation we cannot provide.
  - the create-at-root bind mounts **fall back to the Landlock carve**: existing
    files and subdirectories stay writable, only *new* entries directly at a root
    that has a handoff below it are blocked, and `explain` prints a one-line
    warning. (Landlock cannot express "allow write to X but deny X/y".)

  The base sandbox — FS carve + trust-handoff, read-deny, per-port network,
  resource caps, the broker — needs **no** namespace and runs unprivileged on
  these hardened hosts. macOS has none of these limits.


- **Domain egress on non-root Linux.** Landlock's network filter is port-based,
  not address-based, so a port grant alone cannot stop an agent from reaching an
  external host on the broker's port. On **Linux as root** this is closed: the
  agent runs in a network namespace whose only route is a veth to the broker, with
  no default route, and it fails closed if the namespace can't be verified. On
  **macOS** the Seatbelt profile filters egress by remote address, so the gap never
  applied. On **non-root Linux**, where that namespace can't be created,
  `--allow-domain` falls back to the port grant with a loud warning. That is
  scoped egress for a trusted agent, not containment of hostile code. The broker is
  a host:port capability: a TCP tunnel with TLS end to end, so it does not inspect
  SNI or certificates.

- **A write-deny on a path that does not exist yet (Linux).** Landlock matches
  inodes, so an explicit `--write-deny` on an absent path is enforced by
  withholding the nearest existing ancestor: its existing children stay writable,
  but no new entry can be created directly in it. Such a policy uses the carve
  instead of the bind-mount strategy. macOS matches by path and has no such cost.
  Earlier versions silently dropped an absent explicit deny; it is now enforced.

- **Absent *nested* handoff paths under the bind-mount strategy (Linux root).**
  When the whole workspace is granted writable and existing handoff paths are
  pinned read-only (the root/container strategy), a handoff path **nested below the
  root that does not exist yet** — e.g. a new `sub/.gitmodules`, or
  `.claude/skills/` when only `.claude/` exists — can still be created, because
  there is nothing to bind read-only. Existing nested handoff paths and all
  top-level ones are protected. macOS (regex) covers the absent case; closing it on
  Linux (carve the absent handoff's existing ancestor even under bind mounts) is on
  the roadmap. `explain` states the active strategy.

- **Relocating a protected path by moving its ancestor — partly open.** On macOS
  a read-denied secret inside a writable root cannot be relocated out of its deny
  by renaming an ancestor: the deny is pinned and every ancestor up to the root is
  unlink-blocked. Still open and tracked on the roadmap, measured on 2026-10-15:
  on **Linux**, renaming an ancestor of a read-denied secret or of an explicit
  write-deny inside a writable root can move it out from under its carve; on **both
  systems**, moving or swapping a whole `.git` directory (rename / `RENAME_EXCHANGE`)
  and planting a fresh config; and on **macOS**, moving an entire writable root into
  another writable root (`mv root otherRoot/x`) — the same move is already blocked on
  Linux. Until each is closed with a fix and a scenario, these are not claimed.
