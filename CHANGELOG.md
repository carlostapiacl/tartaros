# Changelog

All notable changes to TartarOS. This project is pre-1.0; the format is
loosely [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Fixed
- **The egress broker passes a forwarded request's body on.** As a plain-HTTP
  forward proxy it sent the request line and headers and never the body, so a
  POST through it reached the upstream as headers alone and hung until a
  timeout (curl got no answer; Claude Code retried until `ECONNRESET` against an
  MCP server on a declared loopback port). The body is now streamed exactly as
  framed, by `Content-Length` or chunked. A request whose framing is ambiguous
  (both headers, two lengths that disagree, a coding other than `chunked`) is
  refused with 400 instead of guessed at. Hop-by-hop headers (`Connection`,
  `Proxy-Connection`, `Keep-Alive`, `TE`, `Trailer`, `Upgrade`) are no longer
  passed upstream: a client's `keep-alive` next to the broker's own `close` let
  the upstream hold the connection open after answering. Capability mode
  (origin-form requests) still sends no request body; that is separate.

## [0.1.0-alpha.7] — 2026-10-21

Linux parity with bubblewrap-based sandboxes where the host allows namespaces
(root, or unprivileged user namespaces). Measured against sandbox-conformance's
frozen corpus: 132 → 151 contained, 26 → 7 escaped.

### Changed
- **Every Linux run gets a private PID namespace** where namespaces are available,
  with a small init as PID 1 and the agent as PID 2 (as bubblewrap does). The agent
  cannot see or signal a host process, and when the run ends or the supervisor dies
  the whole tree goes with it, background children included. The init runs under
  the agent's seccomp filters. `--isolate-pids` is now implied there.
- **No network grant means an empty network namespace** (no `--net`, port, domain
  or egress namespace): abstract unix sockets live per network namespace, and
  Landlock on kernels before 6.12 does not scope them.
- **Outside the writable roots the tree is read-only** (a private mount namespace
  with every other mount remounted read-only, flags kept): Landlock does not
  mediate chmod, utimes or extended attributes, so these were possible on any file
  the agent could reach.
- **Shell rc files, `.gitconfig` and `.ripgreprc` in a writable root are
  protected by default**, as sandbox-runtime does (they were opt-in with
  `--protect-home-handoff`, still accepted). `--allow-home-handoff` lifts it for a
  dotfiles repo; a config file can set `protect_home_handoff = false`.

### Fixed
- **Absent handoff paths can no longer be created on Linux** (`.mcp.json`,
  `.claude/…`, a repo's absent `.git/hooks`, the rc files). With a mount namespace
  an empty read-only placeholder sits at the first missing component for the run
  and is removed after it; with namespaces `--materialize` no longer leaves
  permanent files.
- **Renaming a directory that holds a protected path no longer frees it (Linux).**
  `mv .git .git-old && mkdir .git`, a `renameat2` exchange of `.git`, and moving
  the directory above an explicit `--write-deny`/`--read-deny` all fail (the
  directory is a mount point, EBUSY).
- **A unix socket inside a read-denied directory is unreachable (Linux):** the
  directory is covered by an empty tmpfs; Landlock does not mediate `connect()`.
- **A read-allow that is a symlink planted in a writable root re-opens nothing new
  (Linux).** In the granted model (`--read-deny /` plus allows) `work/docs ->
  ~/.ssh` re-opened the secret; such an allow now counts only where another allow
  already covers its target.
- **A nested tartaros under tartaros keeps its writable root (Linux):** denies that
  already sit on a read-only mount (the outer run's binds) are not carved again.

## [0.1.0-alpha.6] — 2026-10-21

### Changed
- **A refused policy exits 78 (EX_CONFIG).** A policy the backend cannot enforce
  (a `validate` refusal, or a `--settings` field it cannot guarantee, also from
  `explain`) used to exit 1 or 2, the same codes as a startup failure or a bad command
  line, so a caller could not tell "refused your policy" from "could not start". Now:
  78 refused, nothing ran; 2 bad command line; 1 could not start or run. Callers that
  treat any non-zero as a refusal are unaffected.

### Fixed
- **`--isolate-proc` no longer hides the agent's own `/proc/self` (Linux).** The
  Landlock read-deny on `/proc` also denied `/proc/self/status` and `/proc/self/maps`,
  breaking ordinary tools. Where the host allows namespaces it now runs the agent in
  a private PID namespace with a fresh `/proc`: every host process (the supervisor
  included) is invisible and `/proc/self` works. Without namespaces the read-deny
  stays. `explain` says which one applies.
- **A writable root inside a `--read-deny` is readable.** `--write V/w --read-deny V`
  left `V/w` writable but unreadable. Writable roots are now re-allowed for reading
  like `--read-allow`, on Linux and macOS; a deny deeper inside the root still wins.
- **`/dev/shm` is private by default (Linux).** It was isolated only under
  `--isolate-pids`/`--isolate-net`, so a default run could leave files in the host's
  `/dev/shm` or use it as a channel. Every run that can have its own mount namespace
  (root, or a host that allows unprivileged user namespaces) now gets a fresh tmpfs
  there. Where the host forbids namespaces it stays shared, and `explain` says so.
- **`--isolate-net` alone could mount over the host's `/dev/shm` (Linux, root).** It
  unshares only the network namespace, and the private `/dev/shm` tmpfs was mounted
  without a mount namespace of its own. It now always gets one (non-root, the same
  mount failed and aborted the run).

## [0.1.0-alpha.5] — 2026-10-21

### Fixed
- **`allowMachLookup` from `--settings` is additive again, as in sandbox-runtime
  (macOS).** alpha.4 read the list as the *complete* set of allowed services, so a
  headless-browser role that only lists `org.chromium.Chromium.MachPortRendezvousServer.*`
  lost everything else: the keychain failed (`security: SecKeychainSearchCreateFromAttributes
  … not valid`) and configd, opendirectoryd.libinfo, notification_center and others
  were denied. A non-empty list now opens sandbox-runtime's curated base of essential
  system services plus the listed prefixes (plus configd/DNSConfiguration under direct
  egress, `--net`). The strict posture — only the listed prefixes — is opt-in with
  the new `--mach-lookup-only`.
- **`--private-tmp` uses a short path.** The dir was `tartaros-tmp-<pid>-<ns>` under
  the launcher's `$TMPDIR`; under `/var/folders/…` Playwright's socket dir reached
  107 bytes and failed (`Socket directory path is too long`). It is now
  `/private/tmp/tartaros-<uid>/tt-<6 random>` (`/tmp/…` on Linux): the base is 0700
  and must be a real directory owned by the caller (a symlink or someone else's dir
  is refused); the run dir is created exclusively, 0700, and removed after the run.

## [0.1.0-alpha.4] — 2026-10-15

### Fixed
- **Trust-handoff cost is now independent of the writable tree size (macOS).**
  Building the Seatbelt profile walked every directory under each writable root to
  enumerate existing handoff surfaces, so a large root (a 22 GB cache, a repo with
  `node_modules/`) took tens of seconds — `explain --write ~/.cache` ~99 s — and
  emitted hundreds of literal rules, which also overflowed `ARG_MAX` when the
  profile rode `sandbox-exec` on argv ("Argument list too long"). The named handoff
  surfaces (`.git`, `.claude`, `.vscode`, …) are already covered at any depth, and
  for paths created during the run, by the Seatbelt **pattern** rules — the
  enumeration was redundant. `gitdir_pointer_handoff` now resolves the one case a
  pattern can't express (a worktree/submodule checkout whose own `.git` is a
  pointer file to a relocated gitdir) **anchored at each writable root**, O(roots)
  rather than O(tree) — the same approach as Codex/sandbox-runtime. `explain
  --write ~/.cache` / `/private/tmp` now run in well under a second with the same
  guarantee.
- **The Seatbelt profile is delivered by file (`sandbox-exec -f`), not argv.** A
  large profile no longer hits `ARG_MAX`; the profile is written to a private 0600
  temp file, deleted when the run ends.

## [0.1.0-alpha.3] — 2026-10-15

### Fixed
- **Renaming a plain sub-directory of a writable root no longer fails (macOS).**
  The ancestor-move-blocking (which stops a protected path being relocated out of
  its deny) was applied to every nested handoff NAME under a writable root,
  including names that do not exist, so it pinned `file-write-unlink` on every
  ancestor directory and a legitimate `mv src src2` on a plain directory was denied.
  `Policy::gitdir_pointer_handoff` now returns only EXISTING surfaces (the absent
  names are already covered any-depth by the Seatbelt regex), so plain directory
  renames work while the protection is unchanged.

### Hardening
- **Moving the whole `.git` dir aside is blocked (macOS).** An agent could
  `mv .git .git-moved && mkdir .git` and plant a fresh `.git/config`/hooks at the
  original path while the protected inodes travelled with the moved dir. macOS now
  denies `file-write-unlink` on the `.git` directory itself (writes inside it —
  objects/refs — stay allowed). Closes `trust-handoff-git-dir-replace` on macOS;
  the Linux case stays open (Landlock governs rename by the parent's write access)
  and is documented in `docs/limits.md`.

## [0.1.0-alpha.2] — 2026-10-15

### Fixed
- **`--settings`: honor srt's loopback-port convention.** An `allowedDomains`
  entry that is a loopback literal with an explicit port (`localhost:N`,
  `127.0.0.1:N`, `[::1]:N`) now grants that local service via `local_ports` (the
  same path as `--port N`: a kernel grant plus a broker loopback-port forward),
  instead of being copied as an external domain the egress broker then refused with
  `403 host not allowed`. A bare loopback host (no port) or a loopback wildcard
  (`localhost:*`, `*.localhost`) is refused (exit 2, apply-fully-or-refuse), as srt
  does; every other `allowedDomains` entry still maps to the broker (HTTPS/443 via
  CONNECT, SSRF defense). `tartaros explain --settings` lists these as
  `loopback ports: [N]`.

### Added
- **Windows backend (native, no WSL, no VM), exercised by the conformance
  corpus.** Two tiers that enforce the same policy model:
  - **`appcontainer` (default, no admin ever).** An AppContainer held by what
    its SID is granted, a private desktop, and a kill-on-close job object for
    process/memory/CPU caps. Reads are deny-by-default (only granted paths are
    readable), stricter than the neutral model.
  - **`sandbox-user` (admin once, then unprivileged).** A dedicated hidden local
    user created by `backends/windows/setup/sandbox-user.ps1`, launched with
    `CreateProcessWithLogonW` into a runner that re-execs the command under a
    `WRITE_RESTRICTED` token. Reads follow the neutral model (everything the host
    allows minus explicit `--read-deny`, as on Linux/macOS); protection is
    explicit deny ACEs bound to the user SID.
  - Trust-handoff is enforced the same way as the other backends, at any depth,
    including a writable root nested inside a handoff surface and a `.git`
    pointer's relocated gitdir. Absent handoff names are held for the run with
    empty placeholder directories that leave no residue in the working tree.
  - A write-ahead ACL journal (`%LOCALAPPDATA%\tartaros\journal`) restores any
    grant left behind by a run that died, recovered by the next run.
  - `tartaros run` dispatches to the backend on Windows (`--log` is refused, no
    collectors yet). The dedicated-user tier blocks all egress (external and
    loopback) with a per-SID WFP filter installed by the setup (`tartaros-wfp`),
    since the Windows firewall exempts loopback; the backend verifies the filter
    is present before each run and refuses fail-closed if it is missing.
  - `--allow-domain` works on the dedicated-user tier: `setup ... -BrokerPort P`
    carves a WFP permit for `127.0.0.1:P` (all else blocked), and `tartaros run`
    starts the egress broker on P and points the agent's HTTPS_PROXY at it, so the
    agent reaches only allowlisted hosts (measured: allowed host CONNECT 200,
    others 403, direct external blocked). Refused fail-closed without a broker
    port or on the appcontainer tier.
  - Selected with `TARTAROS_WINDOWS_TIER`; exercised through the conformance
    bench. Wiring `tartaros run` to the backend on Windows is the next step
    ([roadmap](ROADMAP.md)). Measured on Windows 10 19045 (corpus, `--ignore-os`):
    appcontainer 85/111, sandbox-user 90/111, zero critical violations. Known
    differences and limits are in [`docs/limits.md`](docs/limits.md).
- **`--protect-home-handoff` (opt-in).** Also denies the per-user home-handoff
  surface under the writable roots — shell rc files (`.bashrc`, `.bash_profile`,
  `.zshrc`, `.zprofile`, `.profile`), `.gitconfig` (core.fsmonitor/core.pager run
  commands) and `.ripgreprc` (pre-processor) — denied even if absent. Off by
  default because protecting them breaks editing one's own dotfiles in the box (a
  dotfiles repo is a writable root full of these names). Turn it on when the
  workspace is not a dotfiles repo and that surface is in scope. Also settable in a
  config file (`protect_home_handoff = true`). Closes the `trust-handoff-shell-rc`
  and `trust-handoff-tool-rc` scenarios (previously tracked as a deliberate
  non-goal in `corpus-known-gaps/`).

### Hardening
- **Writable root inside a handoff surface.** A writable root named *inside* a
  directory handoff surface (e.g. `<repo>/.git/hooks/inner`, or under `.vscode` /
  `.claude/commands`) was granted wholesale, because the downward handoff walk
  starts *at* the root and never sees the enclosing surface — so a hook could be
  planted through it. The policy now also checks upward (`ancestor_handoff_denies`)
  and denies such a root; a sibling root under `.git/objects` is untouched (not a
  surface). Closes `trust-handoff-root-inside-hooks` (critical). Verified on macOS
  15.7 and Linux 6.8.

### Hardening found by the cross-sandbox corpus
Running the conformance corpus against the public test suites of other sandboxes
(sandbox-runtime, nono, Codex, bubblewrap) surfaced real gaps. Fixed, each with a
scenario and measured on Linux 6.8 and macOS 15.7:
- **Symlinked deny/allow rules.** On Linux the read and write allow-lists compared
  rules as text and the carve granted symlink entries, so a deny written through a
  symlinked directory (or whose last component was a symlink) left the real file
  readable, and a symlink inside a carved directory re-granted its target. Rules are
  now resolved to real paths and a symlink entry is never granted; a writable root
  that is a symlink out of bounds is refused, not followed.
- **Explicit write-deny on an absent path (Linux).** Was dropped silently; now
  enforced by withholding the nearest existing ancestor (documented cost in
  `docs/limits.md`).
- **Trust-handoff surface.** `.vscode` and `.idea` are protected as whole
  directories; a `.git` pointer file is followed so a gitdir relocated under a
  writable root keeps its hooks/config/modules protected; nested config-handoff
  names are denied even when absent (macOS; the absent-nested case under the Linux
  bind-mount strategy is a documented limit).

### seccomp: close non-IP egress families and namespace clone (Linux)
- When the network is restricted, `socket(AF_PACKET …)` (raw ethernet) and
  `socket(AF_VSOCK …)` (guest↔host) are now denied alongside the existing
  UDP/ICMP/raw close. AF_NETLINK stays allowed — glibc needs it for name resolution
  and it reaches only the kernel, not the network.
- Under `--seccomp-strict`, `clone`/`clone3` with a namespace flag (`CLONE_NEW*`) is
  denied, closing the bypass of the existing `unshare`/`setns` deny (`clone3` returns
  ENOSYS so glibc falls back to the filtered `clone`). Ordinary fork/thread creation
  is unaffected. Corpus 132/132 on Linux with no control broken.

### Isolate /dev/shm in the hardened tiers (Linux)
- With `--isolate-pids`/`--isolate-net` (hostile-code / multi-tenant), `/dev/shm`
  is a fresh private tmpfs in the agent's mount namespace, so the host-shared POSIX
  shared-memory dir is not a cross-run/-tenant side channel and cannot be filled.
  The default local-agent tier keeps the shared dir (documented). Metadata ops
  (chmod/utime/xattr) outside the writable roots stay a documented gap (low impact
  for a non-root agent; the ro-remount close is on the roadmap).

### Conformance runner
- A scenario that does not prove anything can no longer certify green: unknown TOML
  keys and unknown `requires` are contract errors; a `root`/`nonroot` requirement is
  a real host check; before a confined run the attack is checked to succeed WITHOUT
  the sandbox (VACUOUS otherwise), skipped for resource/lifecycle/broker scenarios
  and with `baseline.skip`; `--no-baseline` disables it for re-verification.
- Landlock is detected with a ruleset probe, so it is seen inside containers where
  securityfs is not mounted.
- Contracts can carry a `source` for attribution, and `expect_refusal` for policies
  whose correct outcome is that the sandbox refuses to run.


### Website, evidence and docs
- A project site in `docs/` (GitHub Pages): what TartarOS protects, where the
  boundary is, and the measured results.
- `evidence/2026-10-14/`: the raw output, JSON reports and host stamps of a full run
  on Linux 6.8 (32/32, mutation 0 blind spots, gVisor 20/20) and macOS 15.7 (21/21,
  mutation 0 blind spots), plus Claude Code running confined with egress to one
  domain on macOS.
- `scripts/site-evidence.py` builds `docs/evidence.html` from an evidence run, so
  the published table is generated, not typed.
- New `ROADMAP.md`; the October working log moved to `docs/journal/`. Per-OS limits
  moved to `docs/limits.md`.

### microVM (M-µ1) — uid mapping and the full corpus under runsc
- `GuestUser` (Root / Direct / Mapped). gVisor rejects the user-namespace form; its
  native non-root form (`Direct`) is validated end to end under `runsc`.
- The whole M-µ1-applicable corpus runs under `runsc`, one bundle per scenario
  (`examples/corpus_runsc.rs` + `scripts/corpus-runsc.sh`): 20/20. It found and
  fixed three real bugs: `write_denies` were dropped (now read-only binds),
  `read_allows` were not shared (now read-only shares, deepest wins), and a secret
  that is a regular file could not be masked (now a read-only bind of `/dev/null`).

### Fixed
- `tartaros-bench` wrote `skipped`/`unsupported` inside the `scenarios` array, so
  `reports/last.json` was not valid JSON.

### macOS — opt-in mach-lookup scoping
- `mach-lookup` was allowed broadly (the dynamic linker and ordinary tools look up a
  wide, version-dependent set of system services, so a blind close breaks them).
  Now, when a role provides `network.allowMachLookup` (via `--settings`, its curated
  srt-derived list), the profile switches to **deny-by-default + only those name
  prefixes** — the tight posture integrators asked for. With no list it stays broad
  (back-compat; nothing silently breaks). `allowMachLookup` prefixes were previously
  accepted but inert; they now actually scope.

### Reach declared loopback ports through the broker
- A role's declared `local_ports` (e.g. a local MCP server on `127.0.0.1:8768` or a
  model proxy) are now reachable THROUGH the broker, not just by a direct loopback
  connection. Clients that route everything via `HTTP_PROXY` (ignoring `NO_PROXY`,
  which is how srt is used) previously failed, because the broker only did HTTPS
  CONNECT to allowed domains and its SSRF defense blocked plain-HTTP-to-loopback.
  The broker now forwards plain HTTP and CONNECT to `127.0.0.1`/`::1`/`localhost` on
  EXACTLY the declared `local_ports` — an operator-declared exception to SSRF, with
  no secret injection and no host allow-list. An undeclared loopback port through
  the broker is still refused (403), and a non-loopback host on a declared port is
  not (cannot smuggle an external host). `Broker::with_loopback_ports`; the CLI
  passes the role's `local_ports`. Verified on macOS; broker unit test added.

### NET-01 closed on Linux-root — network-namespace-scoped egress broker
- `--allow-domain` now (Linux, as root) runs the agent in a network namespace whose
  only route is a veth to the broker's host-side address, with **no default route**.
  The agent reaches the broker and nothing else; Landlock's port-based filter is no
  longer the only thing standing between the agent and the open internet. Verified
  on a Linux host: the allowed domain works through the broker (HTTP 200), while a
  direct TCP connect to an external host AND to the host's own public IP on the
  broker port are both blocked; the agent's netns shows only `lo` + the veth.
- **Fail-closed:** if the namespace cannot be built and verified isolating (no
  default route; the connected /30 present), it is torn down and `--allow-domain`
  falls back to the loopback port grant with a loud NET-01 warning (the documented
  non-guarantee) — never a silent weaker mode. The namespace, veth and a scoped
  INPUT firewall rule (for hosts with a default-DROP INPUT policy) are torn down
  after the run. Needs root + iproute2; on macOS the Seatbelt profile already
  filters egress by address, so the gap never applied there.

### macOS — allow signalling same-sandbox processes
- The Seatbelt profile allowed `signal` only to `(target self)`, so a process
  could not signal its own children — killing a timed-out subprocess or closing a
  headless browser (`@playwright/mcp`, and how Claude Code terminates Bash
  commands) failed with `EPERM`. Now `(allow signal (target same-sandbox))`:
  signals to any process in THIS sandbox are allowed, to processes outside it still
  denied (the scope srt uses). Verified: `sh -c 'sleep 30 & kill $!; echo kill=$?'`
  prints `kill=0`, and `kill -0 1` (outside) stays denied.

### Audit response (external review @ 3096508)
- **POL-01 (P0, fixed):** `--settings` accepted an any-depth `denyRead` pattern
  (e.g. `**/.claude/**`) by equivalence with the trust-handoff set — but that set
  protects WRITES, not reads, so the read-deny was silently not applied, breaking
  the apply-fully-or-refuse contract. Any-depth read-denies are now **refused**
  (no any-depth read engine exists); any-depth write-denies still map to the
  handoff set. Verified on macOS + Linux.
- **`explain` secret redaction (P1, fixed):** `explain` printed `--env KEY=VALUE`
  values verbatim (a secret could land in logs/CI). It now shows only names:
  `KEY=<redacted>` for an explicit set, `KEY (inherited)` for a passthrough.
- **microVM OCI egress (P1, fixed):** the config omitted the network namespace when
  egress was wanted, which under an OCI runtime means sharing the HOST network
  (unbrokered egress). The network namespace is now **always** isolated (fail-closed);
  the scoped-egress bridge is tracked future work.
- **NET-01 (P0, confirmed + documented, closure tracked):** reproduced on a Linux
  host — `--allow-domain` grants the broker's loopback port via Landlock, whose
  filter is port-based not address-based, so a malicious agent that learns the port
  can connect directly to an external host on it, bypassing the broker. Corrected
  the overclaims (README/SECURITY/code no longer call the broker airtight), added a
  loud runtime warning, and documented it as a non-guarantee: `--allow-domain` is
  scoped egress for a trusted-but-fallible agent, not hostile-code containment. The
  real closure is a network-namespace-scoped broker (no external route) — tracked.

### microVM (M-µ1) — validated against a real runtime (runsc/gVisor)
- Ran the generated OCI `config.json` + a busybox rootfs under `runsc run`
  (systrap platform, no KVM). Confirmed by the runtime, not just unit tests:
  workspace rw bind works, a read-denied dir is masked, `/proc` is present, and
  `CapEff: 0000000000000000` (every capability dropped).
- **Fix a bug only a real runtime revealed:** `to_oci_config` emitted read-only
  bind mounts for trust-handoff paths that do not exist on disk (the set is
  protect-even-if-absent). A missing bind source makes runsc abort the whole
  sandbox, so absent bind sources are now skipped. Added an `emit_oci` example
  (prints the config for a given rootfs/workspace) and a regression test that an
  absent handoff path is not emitted as a bind.

### CLI fixes (found by running the README example verbatim)
- **Relative paths now work.** `--write`/`--read-deny`/`--read-allow`/`--write-deny`
  (and the same keys in a `--config` file) accept relative paths, resolved to
  absolute against the current working directory at launch. Before, a `./repo`
  was rejected with "writable root must be absolute" — so the documented CLI
  example did not run as written. Glob patterns stay relative by design.
- **`--max-mem` on macOS is refused cleanly instead of crashing.** The Darwin
  kernel does not enforce `RLIMIT_AS`, so `setrlimit(RLIMIT_AS)` returns `EINVAL`
  and every run with `--max-mem` aborted with a cryptic `spawning sandbox-exec:
  Invalid argument`. It is now refused up front with a clear message (like the
  other macOS-unsupported flags) and `explain` states it is not available there;
  the memory cap remains available on Linux via cgroup. `--max-cpu`/`--max-procs`
  were and remain enforced on macOS via RLIMIT. Regression test added.

### Secrets — environment scrubbing (F-13)
- A launcher's environment routinely holds credentials (`AWS_SECRET_ACCESS_KEY`,
  `GITHUB_TOKEN`, …). They are inherited at `exec` and are **not** governed by
  Landlock/Seatbelt, so a confined agent could read them from its own environment
  or `/proc/self/environ` — a real secret-leak vector (F-13, confirmed on macOS).
  The backend now **scrubs the child's environment to a safe allowlist by default**
  (`PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`, `LANG`, `LC_*`, `TERM`, `TZ`, `PWD`,
  `TMPDIR`/`TMP`/`TEMP`, and the proxy vars the egress broker sets) before spawning.
- `--env KEY` carries one launcher variable through; `--env KEY=VALUE` sets one
  explicitly; `--inherit-env` opts back into full passthrough for trusted local use.
- Enforced at the **spawn layer** (`Policy::child_env`, applied by both backends via
  `env_clear`), so the guarantee holds for any embedder, not just the CLI; `explain`
  prints the exact env policy. Regression `env-secret-scrub` + mutation
  `drop-env-scrub` (0 blind spots).

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
  agent cannot OOM the supervisor. Fuzzed (F-12): `read_line_capped` and
  `parse_abs_uri` are panic-free and byte-bounded over thousands of random/
  adversarial inputs, and the broker survives a barrage of garbage connections
  (binary, partial, empty authority) — a legitimate request still gets served.
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
  log is a sampled observation feed for visibility and intent analysis, never the
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
- 31-scenario corpus; PASS / VIOLATION / CONTROL_BROKE / INFRA_ERROR / SKIPPED /
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
