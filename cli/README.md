# seisin-sandbox CLI

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

Example — run an agent over a repo, deny its SSH keys, log what it attempts:

```
seisin-sandbox run --role dev --write ./repo --read-deny ~/.ssh \
  --port 8001 --timeout 600 --log effects.jsonl -- claude -p "fix the build"
```

The exit code is the command's (128+signal on signal death, 124 on timeout).
`--log` records every boundary-crossing attempt first-hand — the feed the intent layer reads.
