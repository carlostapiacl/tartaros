# tartaros CLI

Subcommands: `run` (confine a command), `explain` (print what a policy grants,
without running — for auditing a profile before deploying it), `version`, `help`.

Run a command confined by a policy, on the OS backend (Landlock / Seatbelt).

```
tartaros run [options] -- <command> [args...]
```

**Filesystem**

| option | meaning |
|---|---|
| `--write DIR` | a writable root (repeatable; relative paths resolve against the cwd) |
| `--write-deny DIR` | deny writes to this path inside a writable root (deny-inside-allow; repeatable) |
| `--read-deny DIR` | deny reads of this path (secrets; repeatable) |
| `--read-allow DIR` | re-allow reads of a branch inside a read-deny (deepest rule wins; repeatable) |
| `--materialize` | pre-create absent top-level trust-handoff placeholders so the Linux carve protects them |

**Network**

| option | meaning |
|---|---|
| `--port N` | allow loopback TCP to this port (repeatable) |
| `--allow-domain HOST` | scope egress to this domain via the broker (HTTPS/CONNECT on 443, SSRF-defended); no other egress (repeatable) |
| `--net` | allow all network (default: deny — and seccomp also denies UDP/ICMP/raw, not just TCP) |
| `--isolate-net` | empty network namespace (loopback only); belt-and-suspenders over the seccomp egress close |
| `--deny-unix` | deny AF_UNIX sockets (seccomp) — blocks reaching a host daemon socket (docker.sock, D-Bus) |

**Process / kernel hardening**

| option | meaning |
|---|---|
| `--isolate-pids` | private PID + mount namespace (root or an unprivileged user namespace) |
| `--seccomp-strict` | deny dangerous syscalls (module load, kexec, ptrace, bpf, mount, mknod, …) |
| `--isolate-proc` | exclude /proc from reads |
| `--profile NAME` | `local-agent` \| `hostile-code` \| `multi-tenant` — a named tier applied before flags |

**Resources & lifecycle**

| option | meaning |
|---|---|
| `--timeout SECS` | kill the process group after SECS (exit 124) |
| `--max-mem BYTES` | memory cap — cgroup `memory.max` + `RLIMIT_AS` on Linux; falls back to `RLIMIT_AS` (address space) with a warning if no cgroup. **macOS: refused** (Darwin does not enforce `RLIMIT_AS`) — use Linux |
| `--max-procs N` | process cap — cgroup `pids.max` on Linux (**root-proof**); falls back to `RLIMIT_NPROC` (best-effort, root-bypassable) with a warning if no cgroup. **macOS caveat:** `RLIMIT_NPROC` is **per-user**, counting all your processes — a value below the machine's current process count makes the agent fail to `fork` ("Resource temporarily unavailable"); set it high or use Linux |
| `--max-cpu SECS` | CPU-time limit (`RLIMIT_CPU`) |
| `--strict` | guaranteed-or-abort: refuse to run if a requested cap can't be installed as a hard guarantee |

**Browsers / integration (macOS)**

| option | meaning |
|---|---|
| `--private-tmp` | run-private `TMPDIR`, made writable and AF_UNIX-scoped to it (a headless browser's control socket lands there, not the shared temp) |
| `--browser` | minimal extra Seatbelt grants for headless Chromium/Chrome (POSIX shm/sem, IOKit, `kern.proc.pid.`); Linux refuses it |

**Policy sources & logging**

| option | meaning |
|---|---|
| `--role NAME` | label for effect-log attribution |
| `--config FILE` | load a TOML policy file (flags override it); `~` expands to $HOME |
| `--settings FILE` | map a sandbox-runtime `settings.json` onto the policy, applying every field it can enforce and **refusing** (exit 2) anything it cannot |
| `--log FILE` | write the effect log (JSON Lines) of the run (both OS) |

Example — run an agent over a repo, deny its SSH keys, log what it attempts:

```
tartaros run --role dev --write ./repo --read-deny ~/.ssh \
  --port 8001 --timeout 600 --log effects.jsonl -- claude -p "fix the build"
```

## Policy file (one policy → both OS)

Declare a role once and apply it on macOS and Linux:

```toml
role = "dev"
profile = "local-agent"                 # optional named tier, applied before the rest
writable_roots = ["./repo"]
write_denies = ["./repo/dist"]          # deny-inside-allow
read_denies = ["~/.ssh", "~/.aws"]
read_allows = ["./repo/runs/mine"]      # re-allow a branch inside a read-deny
local_ports = [8001, 8081]
net = false                             # default-deny egress (all protocols)
deny_unix_sockets = false
isolate_pids = false
isolate_network = false
materialize_absent_handoff = true
timeout_secs = 600
```

```
tartaros run --config role-dev.toml -- claude -p "fix the build"
```

See [`examples/role-dev.toml`](examples/role-dev.toml). A sandbox-runtime
`settings.json` can instead be mapped with `--settings` (apply-fully-or-refuse); its
`network.allowMachRegister` / `allowMachLookup` fields are macOS-only (Linux refuses
them). `--config` flags are overridden by equivalent command-line flags.

The exit code is the command's (128+signal on signal death, 124 on timeout).
`--log` records every boundary-crossing attempt first-hand — the feed the intent layer reads.

## explain — audit a policy

```
tartaros explain --config role-dev.toml
```

Prints the role, network/ports, writable roots, read-denied secrets, the
trust-handoff protected set expanded to any depth, and the generated Seatbelt
profile (macOS) or Landlock allow-lists (Linux). "Política verificable": a
security team reviews exactly what a profile grants before it ships.

## Observed audit vs guaranteed enforcement

Enforcement (confinement, resource limits, timeout) is **guaranteed** and identical
whether `--log` is on or off — both paths use the same supervisor.

The effect log is **observed** by sampling (`/proc` on Linux, `lsof`/`ps` on macOS):
a very short-lived connection or file read may end between samples and not appear.
It is first-hand and trustworthy, but it is not a complete kernel-event trace — for
that, point a kernel-event collector (eBPF/ES) at the process and feed its output to
the same effect-log format. The sandbox's *guarantees* never depend on the log.
