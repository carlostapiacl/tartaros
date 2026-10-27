# Security Policy

TartarOS is a security tool, so we take reports seriously and ask that they be
handled responsibly.

## Supported versions

TartarOS is pre-1.0 (`v0.1.0-alpha.17`). Only the latest release and `main` are
supported. The security model and its honest limits are documented in the
README ("Honest limits") and in the threat-model profiles
(`--profile local-agent | hostile-code | multi-tenant`).

## Scope

In scope: a bypass of a guarantee TartarOS **claims** — e.g. writing a
trust-handoff file it says it protects, reaching a host the egress policy
denies, a resource cap that does not hold, an agent escaping its confinement or
the supervisor on a supported host (Linux with Landlock + cgroup v2; macOS with
Seatbelt).

Explicitly **out of scope** (documented non-guarantees, not vulnerabilities):

- Kernel-level isolation between tenants. TartarOS runs on a **shared kernel**;
  a kernel exploit can cross the boundary. `multi-tenant` is single-kernel
  hardening only — real tenant isolation needs a microVM backend (not yet
  built; designed in [`docs/microvm-backend.md`](docs/microvm-backend.md)).
- A capability a host cannot provide. These fail closed or are reported
  `UNSUPPORTED`; they are never silently downgraded.
- A difference in defaults or a misconfiguration.
- **Egress scope bypass via the broker's port (NET-01) — closed on Linux-root.**
  Landlock's network filter is port-based, so a port grant alone does not stop an
  agent from reaching an external host on the broker's port. On Linux as root this
  is now closed: the agent runs in a network namespace whose only route is a veth to
  the broker (no default route), fail-closed. On macOS the Seatbelt profile filters
  by remote address, so the gap never applied. The remaining non-guarantee is the
  **non-root Linux fallback**, where the scoped namespace can't be created: there
  `--allow-domain` degrades (with a loud warning) to the port grant — scoped egress
  for a trusted-but-fallible agent, not hostile-code containment. Run as root for
  the closed behavior.

## Reporting a vulnerability

**Please do not open a public issue for a vulnerability.** Instead use GitHub's
private vulnerability reporting (the repository's *Security → Report a
vulnerability* tab), which opens a private advisory.

Include: the version/commit and host (OS, kernel, Landlock/cgroup availability —
`tartaros version` and the `security-bench` environment stamp help), the policy
or profile in effect, and a minimal, reproducible proof of concept. A failing
`security-bench` contract (attack + legitimate control + real-effect assertion)
is the ideal form and the fastest to triage.

We aim to acknowledge within a few days, agree on a disclosure timeline, fix in
`main`, and add a regression scenario to the conformance corpus so the issue
cannot silently return.
