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
- **trust-handoff set + `write_denies`** → the handoff paths and any user-declared
  write-deny (`fs_rules` `Access::Deny`) inside a writable root are shared
  **read-only**, so the agent can read them (git, its own config) but cannot poison
  them. The agent in the guest literally cannot write a ro virtio-fs mount — stronger
  and simpler than the Landlock carve, and it covers *not-yet-existing* paths too
  (closing the Linux bind-mount residual: a ro share of the parent makes new handoff
  files unwritable).
- **`read_allows`** → a re-allowed read branch (even one outside the writable roots)
  is shared **read-only**, so a legitimately-readable branch under a broad deny stays
  visible; a deeper `read_denies` inside it is masked on top (deepest-path-wins).
- **`read_denies`** → a secret inside a shared dir is **masked** so its content never
  reaches the guest: a secret **directory** by an empty read-only tmpfs, a secret
  **file** by a read-only bind of `/dev/null` (a tmpfs cannot mount over a regular
  file). A secret that is only the *parent* of a re-allowed branch is simply never
  shared (not masked), so the branch stays readable. A secret outside every share is
  invisible by default (a VM shares only what is listed).
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
  - [x] **Crate + trait wiring + capability probe landed, fail-closed.**
        `backends/microvm` implements `core::Backend`; `probe_runtime()` reports
        `runsc`/`firecracker`/`/dev/kvm`; `run` refuses (never runs under-confined)
        until guest execution exists. Builds and tests on Linux + macOS (4/4).
  - [x] **Backend-agnostic share mapping landed, unit-tested.** `mount_plan(policy)`
        classifies each host path rw (writable roots) / ro (trust-handoff within
        them) / excluded (secrets inside a root — invisible, stronger than a path
        deny), reusing `trust_handoff_rules()` so the set is identical to the
        shared-kernel backends; `guest_wants_egress()` captures the off-by-default
        NIC. Pure, no runtime needed (6/6 crate tests).
  - [x] **OCI `config.json` emission landed, unit-tested.** `to_oci_config(policy,
        command, rootfs)` emits a standard opencontainers/runtime-spec bundle: the
        command, the `mount_plan` shares (rw bind / ro bind / ro-tmpfs mask for a
        secret), resource limits, and a fresh network namespace when egress is off.
        Hardened to match the Landlock backend so the guest is never *more*
        privileged than it: `noNewPrivileges`, **all capability sets empty**
        (drop-all, else the runtime grants its default caps incl. NET_RAW/MKNOD/
        SETUID), read-only root, `RLIMIT_NOFILE` ceiling, and the standard
        `maskedPaths`/`readonlyPaths` for the /proc and /sys leak channels, plus the
        standard default mounts (/proc, /dev, /dev/pts, /dev/shm, /dev/mqueue, /sys
        ro, /sys/fs/cgroup ro) so the bundle is runnable and that hardening has a
        filesystem to apply to. Pure, no runtime (8/8 crate tests).
  - [x] **`process.user` + uid/gid mapping — closed, validated against runsc.**
        The guest identity is now a [`GuestUser`] knob (`backends/microvm`): `Direct`
        (non-root uid, no userns), `Mapped` (OCI/runc userns form), or `Root` (legacy
        uid-0). Validating against the real runtime settled the design — and the two
        runtimes genuinely disagree, exactly as this item warned:
        - **gVisor rejects the OCI/runc `Mapped` form.** Any spec that declares a
          user namespace (`linux.uidMappings`/`gidMappings`) fails under `runsc
          release-20261005.0` with `cannot create gofer process: gofer: fork/exec
          /proc/self/exe: invalid argument`, independent of the mapping target or
          the platform flag (`systrap`/`ptrace`), on a kernel with userns enabled
          (`max_user_namespaces=15127`). So the textbook "non-root guest behind a
          userns mapped to the host owner" is a runc-class path, **not** a gVisor one.
        - **gVisor's native least-privilege form is `Direct`.** runsc maps a bind's
          ownership guest-uid == host-uid directly (no userns), so when the launcher
          runs as a **non-root** uid that **owns the workspace**, `process.user` set
          to that uid gives a non-root guest with a writable workspace. Validated
          end-to-end under `runsc` (launcher uid 2000): in-guest `id` = `2000:2000`
          (not 0), workspace write succeeds, write outside the ws and to the ro root
          both fail, the read-denied secret stays masked, caps still all dropped.
        So the uid-0-in-guest gap is **closed** for the gVisor phase via `Direct`
        (production launches the backend as a non-root service account owning the
        workspace); `Mapped` stays emitted for the runc/Firecracker-class runtimes of
        M-µ2, where the userns form is honoured.
  - [x] **Validated against a real runtime (runsc/gVisor, systrap platform, no KVM).**
        The generated `config.json` + a busybox rootfs runs under `runsc run`: the
        workspace rw bind works, a read-denied dir is masked (invisible), `/proc` is
        present, and `CapEff: 0000000000000000` — every capability dropped, i.e. the
        guest is no more privileged than the Landlock backend, confirmed by the
        runtime not just unit tests. This surfaced and fixed a real bug a pure test
        could not: `to_oci_config` emitted ro binds for trust-handoff paths that do
        not exist on disk, and a missing bind source makes runsc abort the whole
        sandbox — absent bind sources are now skipped (see `emit_oci` example).
        A second run validated the **trust-handoff differentiator** under gVisor:
        overwriting an EXISTING `.git/hooks/pre-commit` fails with "Read-only file
        system" (the ro bind holds), a normal workspace write succeeds, the masked
        secret is unreadable, and the host hook is untouched. A third run broadened
        the FS + network checks under gVisor: a write OUTSIDE the workspace and to
        the (read-only) root both fail, network egress (`wget 1.1.1.1`) is blocked
        (no NIC — the always-isolated netns), and the read-denied secret stays
        masked. So under a real runtime the microVM config enforces rw-workspace,
        ro-root, outside-write-deny, trust-handoff, secret masking, all-caps-dropped,
        and no-egress — the core guarantees, not just unit-tested JSON.
  - [x] **Corpus run under runsc, scripted bundle per scenario — done; it found
        three real backend bugs.** `backends/microvm/examples/corpus_runsc.rs`
        compiles each `security-bench` corpus TOML to a microVM bundle and runs it
        under `runsc` (non-root `Direct` guest); `scripts/corpus-runsc.sh` is the
        driver (run as root on a Linux host with runsc + docker). All **20 M-µ1-applicable scenarios
        PASS** (FS, secrets, read carves, trust-handoff, mknod, env-scrub, pid-ns) —
        with the SAME real-effect assertions (no secret sentinel leaked, protected
        path unchanged/absent, control works). Running against the real runtime
        surfaced three defects a pure unit test did not:
        1. **`mount_plan` dropped `write_denies`.** A user-declared write-deny inside
           a writable root (`fs_rules` `Access::Deny`) was never emitted, so the
           guest could write it (`write-deny-inside-writable` → VIOLATION). Fixed:
           write-denies now map to a read-only bind (readable, never writable).
        2. **`mount_plan` ignored `read_allows`.** A re-allowed read branch outside
           the writable roots was never shared, so a legitimate read failed
           (`read-allow-*` → control-broke). Fixed: read-allows map to a ro share, and
           a deeper read-deny inside one is masked on top (deepest-path-wins ordering).
        3. **A secret that is a FILE could not be masked.** The mask was an empty
           tmpfs, which cannot mount over a regular file (`runsc: mountpoint isn't a
           directory`) — so the whole sandbox aborted. Fixed: a secret file is masked
           by a read-only bind of `/dev/null` (content gone, reads empty — the secrecy
           property holds), a secret directory by the tmpfs as before.
        The remaining corpus scenarios are intentionally **out of M-µ1 scope**:
        `handoff-materialize-absent` is the documented future-handoff residual, and
        the broker/egress (`broker-credential`, `egress-udp-raw-denied`,
        `isolate-net-egress`, `net-unauthorized-port`), VM-size resource caps
        (`resource-cpu/memory/procs`), and server/IPC/seccomp/lifecycle scenarios are
        M-µ2 work (broker bridge, VM-size limits, teardown-by-destroy), not something
        the gVisor M-µ1 config claims yet.
- **M-µ2 — Firecracker**: guest kernel + rootfs build, virtio-fs shares (rw roots /
  ro handoff), vsock broker bridge, VM-size resource caps, teardown = destroy. Run
  the corpus + the multi-tenant scenarios on a KVM host. This is the tenant-isolation
  guarantee.
- **M-µ3 — warm pool + attestation**: VM pool to amortize boot; signed guest image
  (supply-chain). Then `multi-tenant` may claim kernel isolation in `SECURITY.md`.

Until M-µ2 passes its verification contract, `SECURITY.md` keeps saying multi-tenant
kernel isolation is **not** provided — the claim moves only when it is measured.
