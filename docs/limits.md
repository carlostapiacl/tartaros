# Limits, per OS

TartarOS states what it does **not** guarantee as precisely as what it does. Each
limit below is measured, and the ones with a fix in progress are on the
[roadmap](../ROADMAP.md). Where a host can't provide a protection you asked for,
TartarOS refuses to start or reports it `UNSUPPORTED`; it never runs you with less
than you asked for.


- **macOS teardown is best-effort.** A daemon that calls `setsid()` leaves the
  process group and `kill(-pgid)` misses it; macOS has no `cgroup.kill` or job
  object to match Linux's guarantee. Use Linux for strict teardown.
- **Other processes' environments:** do not count on the sandbox to hide
  another same-user process's environment from the agent. tartaros keeps a
  run's secrets out of its own exec environment (a clean re-exec, see
  docs/broker.md); keep secrets out of exported environments of the processes
  around the agent, the launcher's included.
- **Resource caps on a cgroup-less host degrade to RLIMIT** (bypassable by root)
  and TartarOS warns on stderr rather than pretending to confine.
- **Not-yet-existing handoff paths: covered where Linux has namespaces.** The
  real-world Trust-Handoff attack — poisoning a config/hook that *already exists*
  in the repo the agent works in — is blocked on both OS at any depth. A handoff
  path that does **not exist yet** (pre-planting: a new top-level
  `.claude/settings.json`, `.mcp.json`, a repo's absent `.git/hooks`) is covered on
  macOS by regex. On Linux, since 0.1.0-alpha.7, a run with a mount namespace puts
  an empty read-only placeholder at the first missing component of each top-level
  name and each repo's git internals (sandbox-runtime does the same with
  /dev/null) and removes it when the run ends; a run killed outright leaves them
  behind, empty. Two gaps remain on Linux: an absent handoff name in a **nested**
  directory (`sub/.bashrc`, macOS covers it by pattern), and a repository the agent
  **creates during the run** (its hooks are new; no sandbox measured protects
  that). Without namespaces Linux falls back to the carve and opt-in
  `--materialize`. The home-handoff surface (shell rc, `.gitconfig`,
  `.ripgreprc`) is protected **by default** since 0.1.0-alpha.7, as
  sandbox-runtime does; `--allow-home-handoff` lifts it for a dotfiles repo.
- **Moving the whole `.git` dir aside: blocked on both OS.** `mv .git .git-moved
  && mkdir .git` would plant a fresh `.git/config`/hooks at the original path (the
  protected inodes travel with the moved dir). macOS denies `file-write-unlink` on
  the `.git` directory itself. On Linux with a mount namespace, every dot-directory
  that holds a protected path (and every directory above an explicit
  `--write-deny`/`--read-deny` inside a root) is bound onto itself, so renaming or
  exchanging it fails with EBUSY. Side effect: moving a file across one of those
  directories is a cross-mount rename (EXDEV), which `mv` handles by copying.
  Without namespaces the Linux gap remains.
- **Symlinked handoff dirs in a very large writable root (macOS).** A handoff dir
  reached through a symlink (`proj/.claude -> dotfiles/claude`) canonicalises to a
  target the pattern rules don't name, so it is resolved by a bounded scan. The
  scan stops after 10,000 directories per build so a huge writable root (a 20 GB
  cache, `node_modules/`) never stalls profile generation; past that it warns and
  leaves only the pattern protection (which always covers the non-symlinked
  surfaces). A symlinked handoff dir buried deeper than the cap in such a root is
  not auto-resolved — narrow the writable root to pin it. Cost is otherwise
  independent of the tree (named surfaces are pure pattern rules).
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
- **Namespaces need root or an unprivileged user namespace on Linux.** Where the
  host allows them, every run (since 0.1.0-alpha.7) gets a private PID namespace
  with a small init as PID 1, a private mount namespace in which everything outside
  the writable roots and /dev is read-only (Landlock does not mediate chmod,
  utimes or xattrs), read-denied directories covered by an empty tmpfs (so a unix
  socket there stops resolving), and, when the policy grants no network at all, an
  empty network namespace (abstract unix sockets are per network namespace). These
  require CAP_SYS_ADMIN; a non-root user gets it by entering a user namespace first
  (as bubblewrap does). Where a host forbids
  unprivileged user namespaces (hardened Ubuntu with
  `apparmor_restrict_unprivileged_userns=1`, Debian/Arch with
  `unprivileged_userns_clone=0`, or a container without CAP_SYS_ADMIN) the two
  behaviours differ **by design, never silently**:
  - `--isolate-pids`/`--isolate-net` **refuse to start** with a one-line diagnostic
    that names the exact blocking knob and its remedy — fail-closed, because the
    caller asked for isolation we cannot provide.
  - the create-at-root bind mounts **fall back to the Landlock carve**: existing
    files and subdirectories stay writable, only *new* entries directly at a root
    that has a handoff or an explicit write deny below it are blocked (an
    allowWrite of `/tmp` with a deny on `/tmp/claude` cannot create
    `/tmp/new-file`, but can write `/tmp/some-dir/new-file`), and `explain`
    prints a one-line `warning:` naming the root, the denies and the cause.
    There is no way around it in Landlock itself (checked up to ABI v9, Linux
    7.1, the newest the `landlock` crate in use knows; v8 adds all-thread
    restriction and v9 a right for resolving unix sockets): a rule
    grants rights on a whole hierarchy, a deny is the absence of a rule, and the
    rights that create an entry are the parent's. Granting the root only the
    `MAKE_*` rights would let the agent create entries inside the denied
    directory too, and would not let it write the file it just created. A
    consumer that needs a fresh path should make a subdirectory of the root, or
    allow the run a user namespace.

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
  instead of the bind-mount strategy, on every host, when the absent deny lies
  inside a writable root (or `/dev`); one outside them is unwritable anyway and
  leaves the strategy alone. macOS matches by path and has no such cost.
  Earlier versions silently dropped an absent explicit deny; it is now enforced.

- **A read-deny on a path that does not exist yet (Linux).** The same inode limit:
  the nearest existing ancestor is withheld from the read grant instead. Its
  entries at launch stay readable and it can still be listed, but a file that
  appears in it later cannot be read, nor can a new entry in it. When that
  ancestor lies inside a writable root nothing is withheld (the agent could not
  read back what it writes there), so a secret created later inside the
  workspace is not covered.

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

## Windows

Measured on Windows 10 19045. `tartaros run`, `explain` and `version` dispatch to
the backend (the tier from `TARTAROS_WINDOWS_TIER`); `--log` has no Windows
collectors. The security bench certifies 87 scenarios on Windows, all passing on
both tiers (2026-10-26, 0.1.0-alpha.17).

- **Reads differ by tier.** The `appcontainer` tier is deny-by-default: only
  granted paths are readable, which is stricter than the neutral model and breaks
  the read-model controls (a deny-with-a-reopened-branch, a single-file read-deny).
  The `sandbox-user` tier follows the neutral model (read everything except
  `--read-deny`), matching Linux/macOS, at the cost of a one-time admin setup.
  Pick the tier that matches what you need.
- **Egress on the `sandbox-user` tier.** All egress for the sandbox user —
  external *and* loopback — is blocked by a per-SID WFP filter the setup installs
  (`tartaros-wfp`), since the Windows firewall exempts loopback and cannot. The
  backend verifies that filter is present before each run and refuses (fail-closed)
  if it is not; it no longer assumes it. The `appcontainer` tier has no network
  capability at all, so its egress and loopback are closed by construction.
- **Domain-scoped egress on the `sandbox-user` tier.** `--allow-domain` is
  supported: the one-time setup (`install -BrokerPort <port>`) carves a WFP permit
  for `127.0.0.1:<port>` and blocks everything else; at run time tartaros starts
  the egress broker on that fixed port and points the agent's `HTTPS_PROXY` at it,
  so the agent reaches only the allowlisted hosts and cannot connect anywhere
  directly (measured: an allowed host's CONNECT returns 200, a non-allowed host
  403, and a direct external socket is blocked by WFP). Without a configured
  broker port, or on the `appcontainer` tier, `--allow-domain` is refused
  fail-closed. Like the other backends this is a blind CONNECT tunnel (TLS
  end-to-end, no SNI/cert inspection). A fixed port is required because a WFP
  permit needs admin and is installed once at setup, not per run.
- **Masked credentials (`--settings`) on the `sandbox-user` tier.** The swap runs
  in the egress broker on the setup's broker port, as on the other backends, and
  the agent is another user, who cannot read tartaros's environment (measured: the
  agent holds the sentinel, no variable of its holds the value, the credential's
  host receives the real one). On the `appcontainer` tier they are refused
  (exit 78): it has no broker channel.
- **No Schannel inside the `sandbox-user` tier.** Windows refuses SSPI credentials
  to a restricted token, so a client on the system TLS stack fails every HTTPS
  connection with `SEC_E_NO_CREDENTIALS` under the `WRITE_RESTRICTED` runner below:
  `curl.exe`, PowerShell's `Invoke-WebRequest`, .NET. Clients with their own TLS
  stack work (OpenSSL or rustls: Node, Python, Git for Windows by default; measured
  with a rustls client). No restricting SID we tried changes it (`RESTRICTED`,
  `Authenticated Users`, `LOCAL`, `INTERACTIVE`, `SYSTEM`). The two ways out were
  measured, over the 16,000 folders two levels under `ProgramData`, `Windows` and
  `Users\Public`: a token with deny-only groups instead of restricting SIDs lets
  Schannel work, and leaves 23 folders writable outside the roots (the restricted
  token leaves one, writable by Everyone), among them installer and updater
  folders (`OneDrive\setup`, `TP-Link\NSISSetup`, `Oracle\Java`) that a
  privileged process later runs from; a low-integrity token keeps writes closed
  and lets Schannel work, but BusyBox fails to start and batch files do not run.
  So the restricted token stays, and a role that needs HTTPS uses a client with
  its own TLS stack.
- **`WRITE_RESTRICTED` runner (sandbox-user).** The command runs under a
  write-restricted token whose restricting SIDs are the user and `Everyone`;
  `Everyone` is required or the loader cannot start a process. A path writable by
  `Everyone` therefore stays writable (one writable only by `Users` or
  `Authenticated Users` does not). Whether a restricted child can inject into its
  own (unrestricted) runner process in the shared job is not yet proven closed.
- **Absent handoff names in an arbitrary subdirectory.** Absent handoff names are
  held for the run with placeholder directories in a writable root, a repo root, a
  repo's `.git/hooks`, and a nested name whose first component exists. A brand-new
  name in an arbitrary subdirectory (e.g. `sub/.gitattributes`) is not held.
- **Concurrent runs on the same writable root.** One run per invocation is the
  model. Two live runs over the same root can race their DACL save/restore; the
  ACL journal recovers only after a run has ended, not between two live ones.
- **No local-port scoping.** Only the broker's port is reachable on the
  `sandbox-user` tier; a `--port` grant is refused. Full network (`--net`) is
  refused on both tiers.
