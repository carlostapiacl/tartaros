# Effect catalog — what we map

Everything an agent attempts toward the outside of its territory, by axis. The
effect log records each attempt (allowed, denied, or merely observed), so a
pattern like a port scan shows up as many events. This is the map; collectors
fill it in. `core::catalog` holds the shared classification so every collector
agrees on what counts as "outside".

## Independence (important)

- **The effect log is a neutral format (JSON Lines), not a dependency.**
  Collectors write it; anything reads it. See `core::effect::EffectEvent`.
- **The intent layer does not depend on seisin-sandbox** and seisin-sandbox does not
  depend on the intent layer. The intent layer reads the log via its own adapter (it also has
  adapters for other sources — it treats this as one replaceable source).
- **Collectors attach to a process tree by pid** — they can watch any agent, not
  only one launched by this sandbox.
- **An integrator**: it runs agents under the sandbox and points
  the intent layer at the effect log. Neither library knows about the integrator.

## The map

| axis | important attempts to capture | collector | status |
|---|---|---|---|
| **network** | outbound connect; port scan (many connects); loopback to a neighbour service the role wasn't granted; DNS to external resolver; bind/listen | `collect::NetworkCollector` (Linux `/proc/net/tcp`) | **first collector built** (parser + classification tested; live read Linux) |
| | same on macOS | `net/lsof` (planned) | ◻️ |
| **file (write)** | write outside the writable roots; write to a trust-handoff path (`.git/hooks`, `.vscode/tasks.json`, `.envrc`, CI config) | enforced today; event capture ◻️ | 🟡 enforced, not yet logged |
| **secret (read)** | read of a secret location (`~/.ssh`, `~/.aws`, `~/.gnupg`, keychains, `.env`, cloud creds) — `core::catalog::looks_like_secret` | `secret` collector (planned: fd/open observation) | ◻️ classification done |
| **process** | exec of an unexpected binary; spawning a shell/curl/nc; reading another process's env/args (KERN_PROCARGS2, `/proc/<pid>/environ`) | `process` collector (planned) | ◻️ |
| **mcp** | loading an MCP server not granted to the role; tool calls that reach outside | `mcp` collector (planned, from policy + process) | ◻️ |

Legend: **built** · 🟡 partial · ◻️ planned (the model and catalog already accept
it; adding it is a new `Collector`, no change to `core`).

## Event shape

Every collector emits the same `EffectEvent`:

```json
{"ts":1760000000000,"role":"qa","axis":"network","action":"connect",
 "target":"8.8.8.8:53","direction":"outside","outcome":"attempted","source":"net/proc"}
```

- `axis` — which boundary (network/file/secret/process/mcp).
- `action` / `target` — free-form, so a new kind of attempt needs no schema change.
- `direction` — within / outside / unknown, per `core::catalog`.
- `outcome` — attempted / allowed / denied (a pure observer records `attempted`).
- `source` — which collector saw it.

## Why observe, not only ask the wall

Capturing denials from the enforcement layer is unreliable (measured: Seatbelt
denials are not dependably retrievable from the macOS unified log; Landlock
returns EPERM without a path on kernels before audit support). So the log is fed
by **collectors that observe the process tree**, the same approach the intent layer's
research validated — and it captures attempts the wall allowed too, which the
enforcement layer never reports.
