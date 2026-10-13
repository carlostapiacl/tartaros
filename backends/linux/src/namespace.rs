//! Private PID / mount / network namespaces and the process-launch helpers that
//! must run in the child before the Landlock lockdown, kept apart from the
//! Landlock / seccomp / cgroup mechanisms. All are `unsafe` (raw syscalls in a
//! post-fork, pre-exec context) and linux-only (this whole module is gated).

/// Put the agent in private namespaces so it cannot see host processes
/// (`isolate_pids`) and/or cannot reach any external network (`isolate_net`).
/// Called from `pre_exec` (child, before the Landlock lockdown) and after the
/// cgroup join.
///
/// - `isolate_net` adds an empty network namespace with only loopback up: no
///   external interface or route, so NO protocol leaves (TCP, UDP, ICMP, raw) —
///   closing the gap that Landlock (TCP connect/bind only) leaves for UDP/ICMP.
/// - `isolate_pids` adds a PID + mount namespace; the caller continues as PID 1
///   of the new PID namespace with a fresh `/proc`, and the fork's parent becomes
///   a thin init that reaps the agent and propagates its exit status (it never
///   returns here).
///
/// Fails closed: if any step is denied (e.g. no CAP_SYS_ADMIN inside an
/// undelegated container), it returns an error and the launch is aborted rather
/// than running without the requested isolation.
pub(crate) unsafe fn enter_namespaces(isolate_pids: bool, isolate_net: bool) -> std::io::Result<()> {
    // CLONE_NEWNET and CLONE_NEWNS apply to this process immediately; CLONE_NEWPID
    // takes effect on the next fork (this process stays in the old PID ns and its
    // first child is PID 1 of the new one).
    let mut flags = 0;
    if isolate_pids {
        flags |= libc::CLONE_NEWNS | libc::CLONE_NEWPID;
    }
    if isolate_net {
        flags |= libc::CLONE_NEWNET;
    }
    if libc::unshare(flags) != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if isolate_pids {
        // Make the mount tree private so our fresh /proc does not propagate to (or
        // from) the host mount namespace.
        let root = c"/";
        if libc::mount(
            std::ptr::null(),
            root.as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let pid = libc::fork();
        if pid < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if pid > 0 {
            // Init shim (stays in the old PID ns): wait for the agent and exit with
            // its status, so the supervisor sees the agent's real exit code.
            //
            // Close every inherited non-stdio fd first. std::process keeps a
            // CLOEXEC exec-status pipe; the agent (G) closes its copy when it
            // execs, but this shim would hold its copy open for the whole run,
            // so Command::spawn() in the parent would BLOCK reading that pipe until
            // the run ends — the supervisor (and its timeout) would never start.
            // Closing here releases the pipe the moment the agent execs.
            close_inherited_fds();
            // Kill-switch: if the supervisor dies, this shim dies too — and its
            // death trips the agent's own PR_SET_PDEATHSIG (its parent is this
            // shim), tearing the whole PID namespace down. Set AFTER the fork
            // (pdeathsig is cleared across fork) and relative to the supervisor.
            set_pdeathsig_kill();
            let mut status: libc::c_int = 0;
            while libc::waitpid(pid, &mut status, 0) < 0 {
                if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                    libc::_exit(1);
                }
            }
            let code = if (status & 0x7f) == 0 {
                (status >> 8) & 0xff // WEXITSTATUS
            } else {
                128 + (status & 0x7f) // 128 + WTERMSIG
            };
            libc::_exit(code);
        }
        // Agent (PID 1 of the new namespace): mount a fresh procfs so /proc
        // reflects this namespace (only our own processes), not the host's.
        let proc_src = c"proc";
        let proc_tgt = c"/proc";
        if libc::mount(
            proc_src.as_ptr(),
            proc_tgt.as_ptr(),
            proc_src.as_ptr(),
            0,
            std::ptr::null(),
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    // Bring up loopback inside the new netns so 127.0.0.1-to-self works; there is
    // still no external interface or route, so nothing can leave the host.
    if isolate_net {
        bring_up_loopback()?;
    }
    Ok(())
}

/// Bring the loopback interface up inside the current (new) network namespace via
/// SIOCGIFFLAGS/SIOCSIFFLAGS. A fresh netns has `lo` DOWN; without this even
/// 127.0.0.1-to-self fails. No external interface exists, so egress stays closed.
pub(crate) unsafe fn bring_up_loopback() -> std::io::Result<()> {
    // SIOCGIFFLAGS/SIOCSIFFLAGS. The ioctl request arg type differs across libc
    // flavours (c_ulong on glibc, c_int on musl), so pass with `as _`. We build
    // `struct ifreq` as a raw byte buffer (name[16] then the flags union) instead
    // of `libc::ifreq`, whose field names differ between gnu and musl, and we read
    // and write the flags as native-endian bytes to avoid an unaligned access.
    const SIOCGIFFLAGS: u64 = 0x8913;
    const SIOCSIFFLAGS: u64 = 0x8914;
    let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut buf = [0u8; 64]; // >= sizeof(struct ifreq) on both arches
    buf[0] = b'l';
    buf[1] = b'o';
    let p = buf.as_mut_ptr() as *mut libc::c_void;
    let mut rc = libc::ioctl(fd, SIOCGIFFLAGS as _, p);
    if rc == 0 {
        let mut flags = i16::from_ne_bytes([buf[16], buf[17]]);
        flags |= (libc::IFF_UP | libc::IFF_RUNNING) as i16;
        buf[16..18].copy_from_slice(&flags.to_ne_bytes());
        rc = libc::ioctl(fd, SIOCSIFFLAGS as _, p);
    }
    let err = std::io::Error::last_os_error();
    libc::close(fd);
    if rc != 0 {
        return Err(err);
    }
    Ok(())
}

/// Ask the kernel to SIGKILL this task when its parent dies (`PR_SET_PDEATHSIG`).
/// pdeathsig is cleared across `fork`, so this must be set after the fork and is
/// preserved across the following `execve`. If the parent already died in the
/// (tiny) window since the fork, the signal was missed, so we also exit if we
/// have already been reparented to init in the same PID namespace.
pub(crate) unsafe fn set_pdeathsig_kill() {
    libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong, 0, 0, 0);
    // getppid() == 1 means our original parent is already gone (reparented to the
    // ns init). getppid() == 0 means the parent lives in an ancestor PID namespace
    // (the isolate-pids shim case) — still alive, nothing to do.
    if libc::getppid() == 1 {
        libc::_exit(1);
    }
}

/// Close every inherited fd >= 3 (keep stdio) just before exec. `close_range`
/// (Linux 5.9+) is a single async-signal-safe syscall; fall back to a bounded
/// loop if it is unavailable.
pub(crate) unsafe fn close_inherited_fds() {
    let rc = libc::syscall(libc::SYS_close_range, 3u64, u32::MAX as u64, 0u64);
    if rc != 0 {
        for fd in 3..1024 {
            libc::close(fd);
        }
    }
}

