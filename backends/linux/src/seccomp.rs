//! seccomp filters, split into a COMPILE step (runs in the parent, allocates) and
//! an APPLY step (runs in the child's `pre_exec`, after fork, where allocation is
//! unsafe — a multithreaded parent could hold the malloc lock at fork and deadlock
//! the child, review #7). The parent builds the BPF programs with `compile_all`;
//! the child only does `prctl` + `apply_filter` via `apply_all`, which do not
//! allocate. All filters are default-allow, denying only the listed syscalls/args.

use seccompiler::{
    apply_filter, BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
    SeccompFilter, SeccompRule,
};

fn to_io(m: String) -> std::io::Error {
    std::io::Error::other(m)
}

fn finalize(filter: SeccompFilter) -> std::io::Result<BpfProgram> {
    filter.try_into().map_err(|e| to_io(format!("seccomp compile: {e}")))
}

/// Compile every seccomp filter the policy needs, in the PARENT. Returns the BPF
/// programs in apply order. The child applies them with [`apply_all`] — no
/// allocation after the fork.
pub(crate) fn compile_all(
    deny_unix: bool,
    harden: bool,
    restrict_net: bool,
    no_net_grant: bool,
) -> std::io::Result<Vec<BpfProgram>> {
    let mut progs = Vec::new();
    if deny_unix {
        progs.push(compile_deny_af_unix()?);
    }
    if harden {
        progs.push(compile_harden_syscalls()?);
    }
    if restrict_net {
        progs.push(compile_deny_inet_dgram_raw()?);
        // Also close the non-IP egress/host-comms families: AF_PACKET (raw
        // ethernet) and AF_VSOCK (guest<->host). AF_UNIX stays: it is local IPC.
        // AF_NETLINK stays while the run has some network grant: glibc asks it
        // which address families are configured before resolving, and tools list
        // interfaces through it. With no grant at all there is nothing to resolve
        // and nothing to list, so it goes too, as Codex closes it (netlink is also
        // the way to the kernel's audit, uevent and other non-route families).
        let mut families = vec![libc::AF_PACKET, 40 /* AF_VSOCK */];
        if no_net_grant {
            families.push(libc::AF_NETLINK);
        }
        progs.push(compile_deny_socket_families(&families)?);
    }
    if harden {
        // clone3 hides its flags behind a struct pointer seccomp can't inspect, so
        // deny it with ENOSYS; glibc then falls back to clone(), whose flags we DO
        // filter (namespace bits) in compile_harden_syscalls.
        progs.push(compile_deny_clone3_enosys()?);
    }
    // io_uring can create/connect sockets bypassing the socket() filters above, so
    // deny it whenever any socket filter is active (review #4).
    if restrict_net || deny_unix || harden {
        progs.push(compile_deny_io_uring()?);
    }
    Ok(progs)
}

/// Apply pre-compiled filters in the CHILD. Async-signal-safe: sets no-new-privs
/// (required to load a filter unprivileged) and calls `apply_filter` per program —
/// both are `prctl`-family syscalls that do not allocate.
pub(crate) fn apply_all(progs: &[BpfProgram]) -> std::io::Result<()> {
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    for prog in progs {
        apply_filter(prog).map_err(|e| to_io(format!("seccomp apply: {e}")))?;
    }
    Ok(())
}

// libc's musl bindings for aarch64 lack it; 294 is the kernel's number there
// (asm-generic unistd).
#[cfg(all(target_arch = "aarch64", target_env = "musl"))]
const SYS_KEXEC_FILE_LOAD: libc::c_long = 294;
#[cfg(not(all(target_arch = "aarch64", target_env = "musl")))]
const SYS_KEXEC_FILE_LOAD: libc::c_long = libc::SYS_kexec_file_load;
#[cfg(all(target_arch = "aarch64", target_env = "gnu"))]
const _: () = assert!(libc::SYS_kexec_file_load == 294);

/// Deny a curated set of dangerous, rarely-needed syscalls (default-allow; listed
/// return EPERM). Shrinks the kernel attack surface a multi-tenant escape exploits.
/// Ordinary agent tools (sh, cat, ls, git, python3, curl, compilers) do not use
/// these. Includes device-node creation (`mknod`/`mknodat`, review #3).
fn compile_harden_syscalls() -> std::io::Result<BpfProgram> {
    // Only x86_64 pushes more (below).
    #[cfg_attr(not(target_arch = "x86_64"), allow(unused_mut))]
    let mut deny: Vec<libc::c_long> = vec![
        // load/unload kernel code
        libc::SYS_init_module, libc::SYS_finit_module, libc::SYS_delete_module,
        libc::SYS_kexec_load, SYS_KEXEC_FILE_LOAD,
        // kernel keyring
        libc::SYS_add_key, libc::SYS_keyctl, libc::SYS_request_key,
        // powerful kernel interfaces
        libc::SYS_bpf, libc::SYS_perf_event_open, libc::SYS_userfaultfd,
        // cross-process inspection / injection
        libc::SYS_ptrace, libc::SYS_process_vm_readv, libc::SYS_process_vm_writev,
        // reshape the mount / namespace world after lockdown
        libc::SYS_mount, libc::SYS_umount2, libc::SYS_pivot_root, libc::SYS_chroot,
        libc::SYS_unshare, libc::SYS_setns,
        // host-wide state
        libc::SYS_reboot, libc::SYS_acct, libc::SYS_swapon, libc::SYS_swapoff,
        libc::SYS_settimeofday, libc::SYS_clock_settime, libc::SYS_adjtimex,
        // device-node creation: a root agent could mknod a block device and read
        // the raw disk, bypassing path-based confinement (review #3). mknodat is on
        // every arch; the legacy mknod is x86-only (added below).
        libc::SYS_mknodat,
    ];
    #[cfg(target_arch = "x86_64")]
    {
        // x86-only port I/O and the legacy mknod.
        deny.push(libc::SYS_iopl);
        deny.push(libc::SYS_ioperm);
        deny.push(libc::SYS_mknod);
    }

    let mut map = std::collections::BTreeMap::new();
    for nr in deny {
        map.insert(nr, Vec::new()); // empty rule list = match unconditionally
    }
    // clone(2) with a namespace flag is the other way (besides unshare/setns) to
    // enter a new user/mount/net/... namespace after lockdown. clone is also how
    // every fork/thread is created, so deny it ONLY when a CLONE_NEW* bit is set:
    // one rule per bit (arg 0 is the flags word on both x86_64 and aarch64).
    // From libc, not by hand: 0x100 written here as CLONE_NEWTIME (which is 0x80)
    // was CLONE_VM, so every thread creation (clone3 is ENOSYS, so glibc uses
    // clone) got EPERM under harden_syscalls.
    const CLONE_NEW_BITS: &[u64] = &[
        libc::CLONE_NEWTIME as u64,
        libc::CLONE_NEWCGROUP as u64,
        libc::CLONE_NEWUTS as u64,
        libc::CLONE_NEWIPC as u64,
        libc::CLONE_NEWUSER as u64,
        libc::CLONE_NEWPID as u64,
        libc::CLONE_NEWNET as u64,
        libc::CLONE_NEWNS as u64,
    ];
    let mut clone_rules = Vec::new();
    for bit in CLONE_NEW_BITS {
        let cond = SeccompCondition::new(0, SeccompCmpArgLen::Qword, SeccompCmpOp::MaskedEq(*bit), *bit)
            .map_err(|e| to_io(format!("seccomp cond: {e}")))?;
        clone_rules.push(SeccompRule::new(vec![cond]).map_err(|e| to_io(format!("seccomp rule: {e}")))?);
    }
    map.insert(libc::SYS_clone, clone_rules);
    let filter = SeccompFilter::new(
        map,
        SeccompAction::Allow,                     // default: allow
        SeccompAction::Errno(libc::EPERM as u32), // denied syscalls
        std::env::consts::ARCH.try_into().map_err(|e| to_io(format!("seccomp arch: {e}")))?,
    )
    .map_err(|e| to_io(format!("seccomp filter: {e}")))?;
    finalize(filter)
}

/// Deny `socket(family, …)` for each listed family (any type), returning EPERM.
/// Used to close AF_PACKET/AF_VSOCK (and AF_NETLINK with no network grant) when
/// the network is restricted.
fn compile_deny_socket_families(families: &[i32]) -> std::io::Result<BpfProgram> {
    let mut rules = Vec::new();
    for fam in families {
        let cond = SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, *fam as u64)
            .map_err(|e| to_io(format!("seccomp cond: {e}")))?;
        rules.push(SeccompRule::new(vec![cond]).map_err(|e| to_io(format!("seccomp rule: {e}")))?);
    }
    let mut map = std::collections::BTreeMap::new();
    map.insert(libc::SYS_socket, rules);
    let filter = SeccompFilter::new(
        map,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EAFNOSUPPORT as u32),
        std::env::consts::ARCH.try_into().map_err(|e| to_io(format!("seccomp arch: {e}")))?,
    )
    .map_err(|e| to_io(format!("seccomp filter: {e}")))?;
    finalize(filter)
}

/// Deny `clone3` with ENOSYS so a caller (glibc) falls back to `clone`, whose
/// namespace flags ARE filtered. clone3's flags live behind a pointer seccomp
/// cannot read, so it cannot be filtered in place.
fn compile_deny_clone3_enosys() -> std::io::Result<BpfProgram> {
    let mut map = std::collections::BTreeMap::new();
    map.insert(libc::SYS_clone3, Vec::new()); // unconditional
    let filter = SeccompFilter::new(
        map,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS as u32),
        std::env::consts::ARCH.try_into().map_err(|e| to_io(format!("seccomp arch: {e}")))?,
    )
    .map_err(|e| to_io(format!("seccomp filter: {e}")))?;
    finalize(filter)
}

/// Deny io_uring (review #4 / F-1 bypass): `IORING_OP_SOCKET`/`CONNECT` create and
/// connect sockets WITHOUT `socket()`/`connect()`, bypassing the socket filters.
/// Denying `io_uring_setup`/`enter`/`register` means no ring can be created.
fn compile_deny_io_uring() -> std::io::Result<BpfProgram> {
    let mut map = std::collections::BTreeMap::new();
    for nr in [libc::SYS_io_uring_setup, libc::SYS_io_uring_enter, libc::SYS_io_uring_register] {
        map.insert(nr, Vec::new()); // match unconditionally
    }
    let filter = SeccompFilter::new(
        map,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        std::env::consts::ARCH.try_into().map_err(|e| to_io(format!("seccomp arch: {e}")))?,
    )
    .map_err(|e| to_io(format!("seccomp filter: {e}")))?;
    finalize(filter)
}

/// Close the UDP/ICMP/raw egress gap (F-1): deny `socket(AF_INET|AF_INET6,
/// SOCK_DGRAM|SOCK_RAW)`, so only TCP streams can be created (Landlock still
/// restricts those to the granted ports / broker). `AF_UNIX` (any type) and TCP are
/// untouched. The `type` arg carries flags (`SOCK_CLOEXEC`/`NONBLOCK`), so we match
/// the low bits (`SOCK_TYPE_MASK`), not an exact value.
fn compile_deny_inet_dgram_raw() -> std::io::Result<BpfProgram> {
    const SOCK_TYPE_MASK: u64 = 0xf;
    let dom = |af: i32| SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, af as u64);
    let typ = |t: i32| {
        SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::MaskedEq(SOCK_TYPE_MASK), t as u64)
    };
    let mut rules = Vec::new();
    for af in [libc::AF_INET, libc::AF_INET6] {
        for t in [libc::SOCK_DGRAM, libc::SOCK_RAW] {
            let r = SeccompRule::new(vec![
                dom(af).map_err(|e| to_io(format!("seccomp cond: {e}")))?,
                typ(t).map_err(|e| to_io(format!("seccomp cond: {e}")))?,
            ])
            .map_err(|e| to_io(format!("seccomp rule: {e}")))?;
            rules.push(r);
        }
    }
    let mut map = std::collections::BTreeMap::new();
    map.insert(libc::SYS_socket, rules);
    let filter = SeccompFilter::new(
        map,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        std::env::consts::ARCH.try_into().map_err(|e| to_io(format!("seccomp arch: {e}")))?,
    )
    .map_err(|e| to_io(format!("seccomp filter: {e}")))?;
    finalize(filter)
}

/// Deny creating `AF_UNIX` sockets (IPC-1). TCP (AF_INET), files, etc. keep working.
fn compile_deny_af_unix() -> std::io::Result<BpfProgram> {
    let cond = SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, libc::AF_UNIX as u64)
        .map_err(|e| to_io(format!("seccomp cond: {e}")))?;
    let rule = SeccompRule::new(vec![cond]).map_err(|e| to_io(format!("seccomp rule: {e}")))?;
    let mut map = std::collections::BTreeMap::new();
    map.insert(libc::SYS_socket, vec![rule]);
    let filter = SeccompFilter::new(
        map,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EACCES as u32),
        std::env::consts::ARCH.try_into().map_err(|e| to_io(format!("seccomp arch: {e}")))?,
    )
    .map_err(|e| to_io(format!("seccomp filter: {e}")))?;
    finalize(filter)
}
