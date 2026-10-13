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

The highest-leverage piece is the log itself. Today TartarOS records denied writes;
the full design records **allowed and denied** events across all four axes, per
role, with timestamps. That single addition closes a sandbox gap *and* gives the
intent layer its first-hand feed. the intent layer treats TartarOS as a replaceable source,
not a hard dependency (there are adapters for other effect collectors).

## Status

See [`ROADMAP.md`](ROADMAP.md). Today: the filesystem write / trust-handoff core
is done and measured on both OS. The effect log, ports/network, secret reads, and
the secret broker are designed and not yet built — see the README status table.
