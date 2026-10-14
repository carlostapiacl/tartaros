# Design — microVM backend (true multi-tenant isolation)

Status: **design, not built.** This is the one honest ceiling TartarOS declares in
[`SECURITY.md`](../SECURITY.md): the Landlock/Seatbelt backends confine an agent on
a **shared kernel**, so a kernel LPE crosses the boundary and the `multi-tenant`
profile does **not** provide tenant isolation. A microVM backend is the only way to
lift that — each agent runs in its own guest kernel, so a guest kernel exploit stays
inside the VM.

This document fixes the design before any code, so that when a KVM-capable host is
available the work is executed against a verification contract rather than improvised.

## Invariant: the policy, CLI, log and bench do not change

The whole point of `core::Backend` is that a new isolation mechanism plugs in
underneath an unchanged policy model. The microVM backend is **another `Backend`
impl** (crate `backends/microvm`) that compiles the SAME `core::Policy` to VM
configuration instead of Landlock/Seatbelt rules. `cli`, the effect-log format, and
`security-bench` are reused verbatim — the corpus must pass under the new backend
with zero contract changes, plus new multi-tenant scenarios the shared-kernel
backends cannot express.

```
          core::Policy  (unchanged)
                 │  compiles to …
   ┌─────────────┼───────────────────────────────┐
   ▼             ▼                                ▼
 Landlock     Seatbelt                     microVM (new)
 (shared kernel)                     guest kernel per agent
```

## Engine choice

| engine | isolation | KVM needed | boot | compat | notes |
|---|---|---|---|---|---|
| **gVisor** (runsc) | user-space kernel (intercepts syscalls) | no (ptrace mode) / yes (KVM mode) | ~tens of ms | partial (44/294 arm64 syscalls unimpl; io_uring partial; `/proc/sys/net/ipv6` gaps) | **phase 1**: verifiable on any Linux, no nested virt |
| **Firecracker** | real VM (KVM) | yes | ~125 ms + guest kernel | full (real Linux guest) | **phase 2**: the actual tenant-isolation guarantee |
| Cloud Hypervisor | real VM (KVM) | yes | ~similar | full, more devices (GPU passthrough path) | alt to Firecracker when device breadth matters |
| Kata Containers | OCI → VM | yes | heavier | full | if an OCI runtime is already the integration point |

Phasing: **gVisor first** (prototype + verify the Backend wiring and the corpus on
any Linux, no KVM), then **Firecracker** for the real guarantee where KVM exists.
Both behind the same `Backend` impl, selected by capability probe + policy.

## How `core::Policy` maps to a VM

- **`writable_roots`** → a **virtio-fs** (or 9p) share of each root, **read-write**,
  so the agent edits the real repo **in place** (persistence preserved — the host
  directory is the backing store, no copy).
- **trust-handoff set + `read_denies`** → the handoff paths and secret dirs are
  shared **read-only** (or not shared at all for secrets). The agent in the guest
  literally cannot write a ro virtio-fs mount — stronger and simpler than the
  Landlock carve, and it covers *not-yet-existing* paths too (closing the Linux
  bind-mount residual: a ro share of the parent makes new handoff files unwritable).
- **network** → no guest NIC by default (= `--isolate-net` for free, all protocols).
  `--allow-domain` runs the existing broker on the **host**, reached from the guest
  over **vsock** (or a single-host tap), so the capability model is unchanged.
- **resource caps** → the VM's own **memory size, vCPU count, and disk image size**
  are hard limits enforced by the VMM, **root-proof by construction** (a guest root
  cannot exceed the VM's RAM/disk). This makes `--max-disk` trivial — it is the
  guest disk image size — closing the one resource gap the shared-kernel backend
  cannot (see README Honest limits).
- **effect log** → collectors run on the **host**, observing the VM boundary
  (vsock traffic, the virtio-fs server's opens, the VMM's metrics). The JSONL format
  and `RecordMode` are unchanged; the collection *point* moves to the host side,
  which is strictly more trustworthy (outside the guest entirely).
- **lifecycle** → boot the microVM, run the agent as guest PID 1 (or under a tiny
  init), teardown = **destroy the VM**: true teardown, nothing outlives it (no
  `cgroup.kill` needed — the VM and its kernel are gone).

## What microVM gives that the shared-kernel backends cannot

- **Tenant isolation**: a guest kernel LPE stays in the guest. `multi-tenant` can
  finally claim kernel isolation (today it honestly says it cannot).
- **No capability/`mknod`/`io_uring`/raw-disk caveats**: the guest has its own
  devices; reading a host block device is impossible (there is none).
- **Future-proof trust-handoff**: ro shares cover absent paths, so the Linux
  bind-mount "future handoff" residual disappears.

## Honest costs (state them, as always)

- **Boot latency**: Firecracker ~125 ms + guest-kernel init vs ~5–9 ms for the
  shared-kernel backends. Mitigate with a warm VM pool; document the trade.
- **Image maintenance**: a guest kernel + minimal rootfs with the agent's toolchain
  must be built and kept current (supply-chain surface — attest it).
- **No GPU / limited devices** on Firecracker (use Cloud Hypervisor if needed).
- **gVisor compat gaps**: some syscalls/io_uring/`/proc` unimplemented — the corpus
  and the agent's real toolchain must be run under runsc and the gaps documented;
  gVisor is a stepping stone, not the final guarantee.
- **KVM requirement** for the real VM path: unavailable on hosts without nested
  virtualization; the backend must probe and fall back (to gVisor ptrace-mode, or to
  the shared-kernel backend with its honest caveat) — never a silent downgrade.

## Verification contract (do not merge without this)

1. The **entire `security-bench` corpus passes** under the microVM backend, same
   PASS/VIOLATION/CONTROL assertions, on a KVM host — proving the policy compiles
   correctly to VM config.
2. **New multi-tenant scenarios** the shared-kernel backends cannot express:
   - two concurrent agents cannot read each other's memory, fs, or `/proc`;
   - a deliberate guest-kernel fault/panic does not affect the host or a sibling VM;
   - `--max-disk` (guest disk image) returns ENOSPC at the limit with the host fs
     unaffected.
3. **Boot-overhead benchmark** (`--perf`) reported alongside the shared-kernel
   numbers, so the latency trade is measured, not hand-waved.
4. **Fall-back path** verified: on a no-KVM host the backend refuses or degrades
   with a named reason (honest-limits contract), never silently.

## Phasing

- **M-µ1 — wiring + gVisor**: `backends/microvm` crate, `Backend` impl, capability
  probe, policy→runsc config, run the corpus under runsc on a plain Linux host. No
  KVM. Proves the abstraction and finds compat gaps cheaply.
- **M-µ2 — Firecracker**: guest kernel + rootfs build, virtio-fs shares (rw roots /
  ro handoff), vsock broker bridge, VM-size resource caps, teardown = destroy. Run
  the corpus + the multi-tenant scenarios on a KVM host. This is the tenant-isolation
  guarantee.
- **M-µ3 — warm pool + attestation**: VM pool to amortize boot; signed guest image
  (supply-chain). Then `multi-tenant` may claim kernel isolation in `SECURITY.md`.

Until M-µ2 passes its verification contract, `SECURITY.md` keeps saying multi-tenant
kernel isolation is **not** provided — the claim moves only when it is measured.
