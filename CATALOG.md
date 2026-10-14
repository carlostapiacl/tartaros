# Effect catalog — what we map

Everything an agent attempts toward the outside of its territory, by axis. The
effect log records each attempt (allowed, denied, or merely observed), so a
pattern like a port scan shows up as many events. This is the map; collectors
fill it in. `core::catalog` holds the shared classification so every collector
agrees on what counts as "outside".

## Independence (important)

- **The effect log is a neutral format (JSON Lines), not a dependency.**
  Collectors write it; anything reads it. See `core::effect::EffectEvent`.
- **Readers bring their own adapter.** TartarOS does not know who reads the log,
  and a reader does not need to link TartarOS — a SIEM, a script, or an
  intent-analysis tool can all consume the same lines.
- **Collectors attach to a process tree by pid** — they can watch any agent, not
  only one launched by this sandbox.
- **An integrator** runs agents under the sandbox and points whatever analysis it
  uses at the effect log; neither side knows about the other.

## The map

| axis | important attempts to capture | collector | status |
|---|---|---|---|
| **network** | outbound connect; port scan (many connects); loopback to a neighbour service the role wasn't granted; DNS to external resolver; bind/listen | `collect::NetworkCollector` (Linux `/proc/net/tcp`, macOS `lsof -i`; `for_policy` wires territory) | **built + enforced, both OS**: `Policy::local_ports` opens only granted loopback ports (macOS live-verified: 8001 ✓, 8787 blocked); collector classifies via `catalog` |
| **file (write)** | files opened for writing by the process tree, classified within / outside the writable roots | `collect::FileCollector` (Linux `/proc/<pid>/fdinfo` write flags, macOS `lsof -F fan`) | **built, both OS** (write-open events; live-verified on Linux and macOS). Honest scope: observes *allowed* writes — a denied write (outside the roots / to a handoff path) is blocked by enforcement before the fd opens, so it is enforced, not logged |
| **secret (read)** | open fd to a secret location (`~/.ssh`, `~/.aws`, `~/.gnupg`, keychains, `.env`, cloud creds) | `collect::SecretCollector` (Linux `/proc/<pid>/fd`, macOS `lsof`) | **built, both OS** (classification tested; live read on Linux and macOS) |
| **process** | spawning a network/exfil tool (curl, nc, ssh…); reading another process's env (`/proc/<pid>/environ` outside own tree) | `collect::ProcessCollector` (Linux `/proc`, macOS `ps`/`lsof`) | **built, both OS** (both signals tested; live read on Linux and macOS) |
| **mcp** | loading an MCP server not granted to the role | `collect::McpCollector` (v1, cmdline heuristic) | **built** (classification tested); precise source later |

Legend: **built** · 🟡 partial · ◻️ planned (the model and catalog already accept
it; adding it is a new `Collector`, no change to `core`).

## Logging modes

Pick how much to record by wrapping the sink in `core::effect::FilterSink` with a
`RecordMode`:

- `Off` — nothing.
- `DeniedOnly` — only what the wall blocked.
- `OutsideOnly` — only attempts that reach outside the territory (allowed or not).
- `Boundary` — outside OR denied (every crossing).
- `All` — everything, including within-territory activity.

Optionally restrict to axes: `FilterSink::new(sink, mode).with_axes([Axis::Network, Axis::Secret])`.

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
by **collectors that observe the process tree** — and it captures attempts the wall allowed too, which the
enforcement layer never reports.
