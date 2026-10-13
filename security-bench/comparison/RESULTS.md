# Cross-backend comparison — seisin-sandbox vs nono

Honest comparison of the same scenarios, **fairly configured** on each backend.
Measured on the Linux test host (Ubuntu 24.04, kernel 6.8, Landlock) 2026-10-13. nono 0.79.0.

> **Methodology (the discipline the B2B review demanded):**
> - Each backend configured the idiomatic way for strict confinement.
> - "Cannot express" is recorded as a capability gap, **not** a vulnerability.
> - A difference in defaults is not a vulnerability. (See the lesson below.)

| scenario | seisin-sandbox | nono 0.79 (`--allow work`) |
|---|---|---|
| write outside the granted territory | blocked | **blocked** (parity) |
| nested `.git/hooks` (trust-handoff) | **blocked** | **allowed — hook planted** |
| secret read-deny inside a writable territory | blocked | **cannot express** (Linux refuses a deny overlapping an allow) |

## The differentiator (fairly measured)

With both backends granted the same writable `work/` dir, nono lets the agent
write `work/nested/.git/hooks/pre-commit` — it has no trust-handoff layer, so a
planted hook runs outside the box on the next `git commit`. seisin denies it (and
the ancestor-rename variant). This is the gap the market research flagged and it
holds up apples-to-apples.

## Honest lesson (a correction we made mid-measurement)

Our first write-outside run reported nono as "VULNERABLE" — a **false positive**:
the "outside" file was under `/tmp`, which nono allows by default for temp files.
Re-run with an outside path under `/root` (not auto-allowed), **nono blocks it**.
Recorded as parity. This is exactly the trap the review warned about: a difference
in defaults, or a misconfiguration, must never be sold as a vulnerability.

## vs sandbox-runtime (Anthropic srt 0.0.78) — measured on a Linux host

| scenario | seisin-sandbox | srt 0.0.78 |
|---|---|---|
| write outside the granted territory | blocked | **blocked** (parity) |
| overwrite `.claude/settings.json` | blocked | **blocked** (parity in this test) |

**Honest note:** srt is the strongest competitor — it has trust-handoff-like
protections, and in this measurement it blocked both scenarios (parity).
We did **not** reproduce a srt disadvantage here, so none is claimed. `.claude/
settings.json` blocked under srt 0.0.78 — to reconcile with an earlier code-level
observation needs a version-specific check; recorded as parity until then.

Where the measured rows differ: deny-inside-allow on
Linux (nono cannot express it; srt uses bwrap). Against nono and the Codex class
the trust-handoff advantage is public and measured (above).

## Not yet compared

OpenShell (NVIDIA); network/port, broker, lifecycle and resource scenarios across
backends. Each needs its idiomatic config before any claim. Reproduce the nono side
with `comparison/nono-scenarios.sh` on a Landlock host (not the dev Mac).
