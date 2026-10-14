# Architecture

Two layers, one vantage point — the kernel, outside the agent.

- **tartaros — the walls + the first-hand effect log.** What the agent *can*
  do, enforced below it; and a record of every effect it attempted, allowed or
  denied.
- **a separate intent-analysis layer — the intent.** What the
  agent was *trying* to do, read from those effects — never from what the agent
  says about itself.

```
                        a policy / orchestration layer
                 territories · ownership · roles · ports · domains · MCP
                                         │
                                         │  compiles the policy
                                         ▼
   ┌─────────────────────────────  tartaros  ─────────────────────────────┐
   │                      THE WALLS  (kernel level, OUTSIDE the agent)           │
   │                                                                             │
   │     ┌───────────────┐                                                       │
   │     │     AGENT      │   every attempt crosses the wall ──┐                 │
   │     │ claude / codex │                                    │                 │
   │     │  / mcp  /  sh  │                                    ▼                 │
   │     └───────────────┘                         ┌──────────────────────┐      │
   │                                                │  DECISION + LOG      │      │
   │   axes the wall sees FIRST-HAND:               │  allowed / denied    │      │
   │                                                │  per role · ts       │      │
   │   📁 files    → trust-handoff write deny ─────▶│                      │      │
   │   🔌 ports/net→ 127.0.0.1:APP yes, others no ─▶│   EFFECT LOG         │      │
   │   🔑 secrets  → broker: capability, not value ▶│   (allow + deny)     │      │
   │   🧩 MCP       → only the role's servers ──────▶│                      │      │
   │                                                └───────────┬──────────┘      │
   │   backend macOS: Seatbelt   ·   backend Linux: Landlock    │                 │
   └────────────────────────────────────────────────────────────┼───────────────┘
                                                                 │
                              effect log  (trustworthy: not what the agent reports)
                                                                 │
                                                                 ▼
   ┌──────────────────────────────────  intent  ───────────────────────────────┐
   │                        THE INTENT  (reads the effects)                     │
   │                                                                            │
   │   real effects ─▶ actions→resources graph ─▶ infer GOAL ─▶ DEVIATION 0..1 │
   │                                                   (1 LLM / session)        │
   │                                                                            │
   │   e.g. goal="fix the mobile checkout" → touched app ports (in scope) = 0.0 │
   │        same goal → reached an off-scope host + read ~/.ssh         = 0.5 ▲ │
   │        …and it rises BEFORE the exfiltration step                          │
   └────────────────────────────────────────────────────────────────────────────┘

   Enforcement (what it CAN do)  +  Intent (what it was TRYING to do)
   — both from the same place: the kernel, outside the agent.
```

## Why first-hand matters

An agent can obfuscate its destination in the text it emits — deviation analysis
over transcripts scores near chance. It cannot touch a port, open a file, or read
a secret without the wall seeing it. So the sandbox is the trustworthy effect
collector that intent analysis needs: the numerator (what was attempted) and the
denominator (what was in scope) both come from the same kernel-level log.

## Independence — who depends on whom

Nothing here is a hard dependency chain. The **effect log is a neutral format**
(JSON Lines), and that format is the only contract:

- **The intent layer does not import tartaros**, and vice versa. The intent layer reads the
  log through its own adapter and treats it as one replaceable source (it has
  others). 
- **Collectors attach to a process tree by pid** — they can watch any agent.
- **An integrator** runs agents under the sandbox and points
  the intent layer at the log; the libraries do not know about it.

The full list of what we capture, by axis, is in [`CATALOG.md`](CATALOG.md).

## The bridge: a complete effect log

The highest-leverage piece is the log itself. TartarOS records **allowed and
denied** events across the network, secret, process, MCP and file-write axes, per
role, with timestamps — `core::effect` (the `EffectEvent` / `Outcome` /
`RecordMode` model) fed by five collectors in `collect/` (network, secret,
process, MCP, file-write), on both OS. The file-write collector observes *allowed* writes; a denied write is
blocked by enforcement before the fd opens, so it is enforced, not logged. The log
is what gives the intent layer its first-hand feed; the intent layer treats TartarOS as a
replaceable source, not a hard dependency (there are adapters for other effect
collectors).

## Status

See [`ROADMAP.md`](ROADMAP.md). Built and measured on both OS: the filesystem
write / trust-handoff core, read-deny of secret dirs with a specificity carve,
per-port loopback network, domain-scoped egress through the broker, the capability
broker (HTTP + HTTPS/CONNECT, mandatory auth, TTL, quota, SSRF defense), resource
caps (cgroup v2 on Linux, RLIMIT on macOS), PID/mount/net isolation on Linux, and
the effect log with its five collectors (including file-write). Still open: a
microVM backend for true multi-tenant isolation, and the the intent layer intent feed. The
per-OS matrix is the README capability table.
