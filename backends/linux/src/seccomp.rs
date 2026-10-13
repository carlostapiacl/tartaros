//! seccomp filters applied in the child just before exec, kept apart from the
//! Landlock / namespace / cgroup mechanisms so each can be read and tested on its
//! own. Both require no_new_privs (set here) and default-allow, denying only the
//! listed syscalls.

/// Install a seccomp filter that denies a curated set of dangerous, rarely-needed
/// syscalls, shrinking the kernel attack surface (the surface a multi-tenant
/// escape would exploit). Default-allow; listed syscalls return EPERM. Ordinary
/// agent tools (sh, cat, ls, git, python3, curl, compilers) do not use these.
pub(crate) fn harden_syscalls() -> std::io::Result<()> {
    use seccompiler::{apply_filter, BpfProgram, SeccompAction, SeccompFilter};
    let to_io = |m: String| std::io::Error::new(std::io::ErrorKind::Other, m);
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }

    // Portable across x86_64 and aarch64. Each entry is matched unconditionally
    // (empty rule list) and denied.
    let mut deny: Vec<libc::c_long> = vec![
        // load/unload kernel code
        libc::SYS_init_module, libc::SYS_finit_module, libc::SYS_delete_module,
        libc::SYS_kexec_load, libc::SYS_kexec_file_load,
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
    ];
    #[cfg(target_arch = "x86_64")]
    {
        // x86-only port I/O.
        deny.push(libc::SYS_iopl);
        deny.push(libc::SYS_ioperm);
    }

    let mut map = std::collections::BTreeMap::new();
    for nr in deny {
        map.insert(nr, Vec::new()); // empty rule list = match unconditionally
    }
    let filter = SeccompFilter::new(
        map,
        SeccompAction::Allow,                      // default: allow
        SeccompAction::Errno(libc::EPERM as u32),  // denied syscalls
        std::env::consts::ARCH.try_into().map_err(|e| to_io(format!("seccomp arch: {e}")))?,
    )
    .map_err(|e| to_io(format!("seccomp filter: {e}")))?;
    let prog: BpfProgram = filter.try_into().map_err(|e| to_io(format!("seccomp compile: {e}")))?;
    apply_filter(&prog).map_err(|e| to_io(format!("seccomp apply: {e}")))?;
    Ok(())
}

/// Deny creating `AF_UNIX` sockets via seccomp (IPC-1). Everything else is
/// allowed, so TCP (AF_INET), files, etc. keep working. Requires no-new-privs,
/// which we set here (Landlock sets it too, but seccomp is applied first).
pub(crate) fn deny_af_unix() -> std::io::Result<()> {
    use seccompiler::{
        apply_filter, BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
        SeccompFilter, SeccompRule,
    };
    let to_io = |m: String| std::io::Error::new(std::io::ErrorKind::Other, m);

    // no_new_privs is required to install a seccomp filter unprivileged.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }

    // Match socket(domain == AF_UNIX, ..) and return EACCES; allow all else.
    let cond = SeccompCondition::new(
        0,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::Eq,
        libc::AF_UNIX as u64,
    )
    .map_err(|e| to_io(format!("seccomp cond: {e}")))?;
    let rule = SeccompRule::new(vec![cond]).map_err(|e| to_io(format!("seccomp rule: {e}")))?;
    let mut map = std::collections::BTreeMap::new();
    map.insert(libc::SYS_socket, vec![rule]);
    let filter = SeccompFilter::new(
        map,
        SeccompAction::Allow,                            // default: allow
        SeccompAction::Errno(libc::EACCES as u32),       // matched: deny
        std::env::consts::ARCH.try_into().map_err(|e| to_io(format!("seccomp arch: {e}")))?,
    )
    .map_err(|e| to_io(format!("seccomp filter: {e}")))?;
    let prog: BpfProgram = filter.try_into().map_err(|e| to_io(format!("seccomp compile: {e}")))?;
    apply_filter(&prog).map_err(|e| to_io(format!("seccomp apply: {e}")))?;
    Ok(())
}
