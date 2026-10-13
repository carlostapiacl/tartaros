# seisin-sandbox CLI

Two subcommands: `run` (confine a command) and `explain` (print what a policy
grants, without running — for auditing a profile before deploying it).

Run a command confined by a policy, on the OS backend (Landlock / Seatbelt).

```
seisin-sandbox run [options] -- <command> [args...]
```

| option | meaning |
|---|---|
| `--role NAME` | label for effect-log attribution |
| `--write DIR` | a writable root (repeatable) |
| `--read-deny DIR` | deny reads of this path (secrets; repeatable) |
| `--port N` | allow loopback TCP to this port (repeatable) |
| `--net` | allow all network (default: denied) |
| `--deny-unix` | deny AF_UNIX sockets (Linux, seccomp) |
| `--materialize` | pre-create absent trust-handoff placeholders (Linux) |
| `--timeout SECS` | kill the process group after SECS (exit 124) |
| `--max-mem BYTES` / `--max-procs N` | resource limits |
| `--isolate-proc` | exclude /proc from reads (Linux) |
| `--log FILE` | write the effect log (JSON Lines) of the run (Linux) |
| `--config FILE` | load a TOML policy file (flags override it); `~` expands to $HOME |

Example — run an agent over a repo, deny its SSH keys, log what it attempts:

```
seisin-sandbox run --role dev --write ./repo --read-deny ~/.ssh \
  --port 8001 --timeout 600 --log effects.jsonl -- claude -p "fix the build"
```

## Policy file (one policy → both OS)

Declare a role once and apply it on macOS and Linux:

```toml
role = "dev"
writable_roots = ["./repo"]
read_denies = ["~/.ssh", "~/.aws"]
local_ports = [8001, 8081]
materialize_absent_handoff = true
timeout_secs = 600
```

```
seisin-sandbox run --config role-dev.toml -- claude -p "fix the build"
```

See [`examples/role-dev.toml`](examples/role-dev.toml).

The exit code is the command's (128+signal on signal death, 124 on timeout).
`--log` records every boundary-crossing attempt first-hand — the feed the intent layer reads.

## explain — audit a policy

```
seisin-sandbox explain --config role-dev.toml
```

Prints the role, network/ports, writable roots, read-denied secrets, the
trust-handoff protected set expanded to any depth, and the generated Seatbelt
profile (macOS) or Landlock allow-lists (Linux). "Política verificable": a
security team reviews exactly what a profile grants before it ships.
