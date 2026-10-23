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
pub(crate) unsafe fn enter_namespaces(
    isolate_pids: bool,
    isolate_net: bool,
    init_filters: &[seccompiler::BpfProgram],
) -> std::io::Result<()> {
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
        // PID 1 stays a small init and the agent runs as PID 2, as bubblewrap
        // does. The kernel drops every signal PID 1 has no handler for, so an
        // agent running as PID 1 would ignore `kill -TERM $$` and a SIGTERM from
        // the supervisor alike. This init reaps orphans and exits with the
        // agent's status the moment the agent exits, which tears the namespace
        // down: nothing the agent left running outlives it.
        let agent = libc::fork();
        if agent < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if agent > 0 {
            close_inherited_fds();
            set_pdeathsig_kill();
            // The init runs under the agent's seccomp filters too: it is the one
            // process in the namespace the agent can always name.
            if crate::seccomp::apply_all(init_filters).is_err() {
                libc::_exit(1);
            }
            let mut status: libc::c_int = 0;
            loop {
                let r = libc::waitpid(-1, &mut status, 0);
                if r == agent {
                    break;
                }
                if r < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
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
    }
    // Bring up loopback inside the new netns so 127.0.0.1-to-self works; there is
    // still no external interface or route, so nothing can leave the host.
    if isolate_net {
        bring_up_loopback()?;
    }
    Ok(())
}

/// Enter a new USER namespace and map the current euid/egid to themselves, which
/// grants CAP_SYS_ADMIN *inside* the namespace — enough to create a mount
/// namespace and bind-mount without being real root. This is how bubblewrap runs
/// unprivileged. Fails closed: if unshare or the uid/gid maps are refused (e.g.
/// AppArmor blocks unprivileged user namespaces on hardened Ubuntu), it returns
/// an error and the caller aborts (the parent only picks this path after a probe
/// said it would work, so a failure here is an unexpected-environment abort, not
/// a silent downgrade).
/// The uid_map and gid_map bytes mapping the current euid/egid to themselves,
/// built in the PARENT (allocation is fine there). fork preserves euid/egid, so
/// these are valid in the child too — passing them in keeps `enter_user_namespace`
/// allocation-free after the fork (review #7).
pub(crate) fn uid_gid_maps() -> (Vec<u8>, Vec<u8>) {
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    (
        format!("{uid} {uid} 1\n").into_bytes(),
        format!("{gid} {gid} 1\n").into_bytes(),
    )
}

/// Enter a new USER namespace and apply the pre-built uid/gid maps (self→self),
/// which grants CAP_SYS_ADMIN *inside* the namespace — enough to create a mount
/// namespace and bind-mount without being real root (bubblewrap's approach). Maps
/// are passed in (built by [`uid_gid_maps`] in the parent) so nothing is allocated
/// after the fork. Fails closed: if unshare or the maps are refused (e.g. AppArmor
/// blocks unprivileged user namespaces on hardened Ubuntu) it returns an error and
/// the caller aborts (a probe already confirmed it would work, so this is an
/// unexpected-environment abort, not a silent downgrade).
pub(crate) unsafe fn enter_user_namespace(uid_map: &[u8], gid_map: &[u8]) -> std::io::Result<()> {
    if libc::unshare(libc::CLONE_NEWUSER) != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // setgroups must be denied before writing gid_map in an unprivileged userns.
    write_proc_self(c"/proc/self/setgroups", b"deny\n")?;
    write_proc_self(c"/proc/self/uid_map", uid_map)?;
    write_proc_self(c"/proc/self/gid_map", gid_map)?;
    Ok(())
}

/// Format a (positive) pid as decimal + '\n' into `buf`, returning the written
/// slice. Async-signal-safe (no allocation) — for the post-fork cgroup.procs write.
pub(crate) fn fmt_pid(buf: &mut [u8; 16], pid: libc::pid_t) -> &[u8] {
    let mut n = if pid < 0 { 0u32 } else { pid as u32 };
    let mut tmp = [0u8; 10];
    let mut i = tmp.len();
    loop {
        i -= 1;
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    let digits = &tmp[i..];
    buf[..digits.len()].copy_from_slice(digits);
    buf[digits.len()] = b'\n';
    &buf[..digits.len() + 1]
}

/// Write `data` to a /proc/self control file with a single open+write (the
/// uid_map/gid_map/setgroups files accept exactly one write). Raw libc so it is
/// safe in the post-fork, pre-exec context.
unsafe fn write_proc_self(path: &std::ffi::CStr, data: &[u8]) -> std::io::Result<()> {
    let fd = libc::open(path.as_ptr(), libc::O_WRONLY);
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let n = libc::write(fd, data.as_ptr() as *const libc::c_void, data.len());
    let err = std::io::Error::last_os_error();
    libc::close(fd);
    if n != data.len() as isize {
        return Err(err);
    }
    Ok(())
}

/// Probe whether this process can create a usable mount namespace for the
/// read-only bind-mount strategy. As root, true only with CAP_SYS_ADMIN;
/// otherwise forks a throwaway child that tries the unprivileged path —
/// user namespace + uid maps + a no-op private remount of `/` — and reports
/// success via its exit code. The probe runs in its own namespaces, so it never
/// affects this process; a false result means we fall back to the Landlock carve.
pub(crate) fn mount_ns_capable() -> bool {
    if unsafe { libc::geteuid() } == 0 {
        // Root has the privilege only with CAP_SYS_ADMIN: a container's root
        // usually runs without it (Docker's default set), and unshare fails.
        return has_cap_sys_admin();
    }
    // Build the maps BEFORE the fork (allocation in the parent is fine).
    let (uid_map, gid_map) = uid_gid_maps();
    unsafe {
        let pid = libc::fork();
        if pid < 0 {
            return false;
        }
        if pid == 0 {
            // Child: attempt the full unprivileged setup; _exit(0) only if it works.
            if enter_user_namespace(&uid_map, &gid_map).is_err() {
                libc::_exit(1);
            }
            if libc::unshare(libc::CLONE_NEWNS) != 0 {
                libc::_exit(1);
            }
            let root = c"/";
            let rc = libc::mount(
                std::ptr::null(),
                root.as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            );
            libc::_exit(if rc == 0 { 0 } else { 1 });
        }
        // Parent: reap the probe and read its verdict.
        let mut status: libc::c_int = 0;
        while libc::waitpid(pid, &mut status, 0) < 0 {
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                return false;
            }
        }
        (status & 0x7f) == 0 && ((status >> 8) & 0xff) == 0
    }
}

/// Whether CAP_SYS_ADMIN is in this process's effective set (`CapEff` in
/// /proc/self/status, bit 21).
fn has_cap_sys_admin() -> bool {
    const CAP_SYS_ADMIN: u32 = 21;
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("CapEff:"))
                .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
        })
        .is_some_and(|eff| eff & (1 << CAP_SYS_ADMIN) != 0)
}

/// Best-effort explanation of WHY unprivileged user namespaces are unavailable,
/// with the concrete remedy. Used for a fail-closed message when `--isolate-pids`,
/// `--isolate-net`, or the bind-mount strategy is requested by a non-root user on
/// a host that forbids them. Reads the kernel knobs the hardened distros use, so
/// the message names the actual blocker instead of a bare EPERM.
pub(crate) fn userns_blocker_hint() -> String {
    let knob = |p: &str| std::fs::read_to_string(p).ok().map(|s| s.trim().to_string());
    if knob("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").as_deref() == Some("1") {
        return "unprivileged user namespaces are restricted by AppArmor \
            (kernel.apparmor_restrict_unprivileged_userns=1, the Ubuntu 23.10+ default). \
            Run tartaros as root, or allow it with `sudo sysctl -w \
            kernel.apparmor_restrict_unprivileged_userns=0`, or install an AppArmor \
            profile granting userns to this binary, or run inside a container that \
            provides CAP_SYS_ADMIN."
            .into();
    }
    if knob("/proc/sys/kernel/unprivileged_userns_clone").as_deref() == Some("0") {
        return "unprivileged user namespaces are disabled \
            (kernel.unprivileged_userns_clone=0, common on hardened Debian/Arch). \
            Run as root, or `sudo sysctl -w kernel.unprivileged_userns_clone=1`, or \
            run inside a container that provides CAP_SYS_ADMIN."
            .into();
    }
    if knob("/proc/sys/user/max_user_namespaces").as_deref() == Some("0") {
        return "user namespaces are capped at zero (user.max_user_namespaces=0). \
            Run as root, raise the cap with `sudo sysctl -w \
            user.max_user_namespaces=<N>`, or run inside a container that provides \
            CAP_SYS_ADMIN."
            .into();
    }
    "this host denies unprivileged user namespaces (no CAP_SYS_ADMIN, and the \
        unshare(CLONE_NEWUSER) was refused — e.g. a container started without \
        CAP_SYS_ADMIN or with a seccomp/AppArmor profile that blocks it). Run \
        tartaros as root, or in a container that grants CAP_SYS_ADMIN."
        .into()
}

/// Protect the trust-handoff set with READ-ONLY bind mounts instead of carving
/// it out of the Landlock write grant. This lets the whole workspace be granted
/// writable (so the agent can create new files at the repo root — which the carve
/// cannot allow while a deny sits below) while the handoff paths stay unwritable
/// at a lower layer (the kernel VFS), exactly as bubblewrap/sandbox-runtime do.
///
/// Each path is bound onto itself as ONE mount (not per-entry — a per-entry bind
/// of `.git` races git's transient lockfiles) and then remounted read-only. The
/// mounts live only in this process's private mount namespace and vanish when it
/// exits, so nothing is left in the real tree.
///
/// `need_unshare` is true when no mount namespace exists yet (no `--isolate-pids`);
/// we create a private one here. Fails closed: any mount error aborts the launch,
/// so the workspace is never left writable with the handoff unprotected.
///
/// The caller must already hold CAP_SYS_ADMIN — real root, or a user namespace
/// entered up front (see `enter_user_namespace`). Entering the user namespace is
/// done once by the caller, not here, so it is shared with `--isolate-pids`.
pub(crate) unsafe fn setup_ro_binds(
    paths: &[std::ffi::CString],
    need_unshare: bool,
) -> std::io::Result<()> {
    if need_unshare {
        enter_private_mount_ns()?;
    }
    for p in paths {
        // Bind the path onto itself (one recursive mount).
        if libc::mount(
            p.as_ptr(),
            p.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REC,
            std::ptr::null(),
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        // Remount that bind read-only. MS_REMOUNT|MS_BIND changes only the mount
        // flags of the bind, not the underlying filesystem.
        if libc::mount(
            std::ptr::null(),
            p.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_REC,
            std::ptr::null(),
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Bind each path onto itself (recursively), read-write, so it becomes a mount
/// point of its own. Two uses: a writable root keeps its write access when the
/// rest of the tree is sealed read-only (the bind copies the flags it has now),
/// and a directory that holds a protected path cannot be renamed or exchanged
/// away (rename fails with EBUSY on a mount point), so `mv .git .git-old && mkdir
/// .git` cannot swap a fresh config in. Fails closed.
pub(crate) unsafe fn pin_mounts(paths: &[std::ffi::CString]) -> std::io::Result<()> {
    for p in paths {
        if libc::mount(
            p.as_ptr(),
            p.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REC,
            std::ptr::null(),
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Remount each mount point read-only, keeping the flags it already has (inside a
/// user namespace a remount that drops a locked nosuid/nodev/noexec/atime flag is
/// refused, so they are read back with statvfs and passed again). Landlock does
/// not mediate chmod, chown, utimes or xattrs, so without this the agent could
/// change the metadata of any file it can reach; a read-only mount refuses them.
/// Best effort per mount: one that cannot be resolved or remounted (an exotic
/// filesystem, a path the user cannot reach) is left as it was, which is the
/// behaviour without sealing.
pub(crate) unsafe fn seal_readonly(mountpoints: &[std::ffi::CString]) {
    const KEEP: [(libc::c_ulong, libc::c_ulong); 6] = [
        (libc::ST_NOSUID, libc::MS_NOSUID),
        (libc::ST_NODEV, libc::MS_NODEV),
        (libc::ST_NOEXEC, libc::MS_NOEXEC),
        (libc::ST_NOATIME, libc::MS_NOATIME),
        (libc::ST_NODIRATIME, libc::MS_NODIRATIME),
        (ST_RELATIME, libc::MS_RELATIME),
    ];
    // The kernel's value (glibc's too); libc's musl bindings do not have it.
    const ST_RELATIME: libc::c_ulong = 0x1000;
    #[cfg(target_env = "gnu")]
    const _: () = assert!(ST_RELATIME == libc::ST_RELATIME);
    for m in mountpoints {
        let mut sv: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(m.as_ptr(), &mut sv) != 0 {
            continue;
        }
        let mut flags = libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY;
        for (st, ms) in KEEP {
            if sv.f_flag & st != 0 {
                flags |= ms;
            }
        }
        let _ = libc::mount(std::ptr::null(), m.as_ptr(), std::ptr::null(), flags, std::ptr::null());
    }
}

/// Cover each read-denied directory with an empty, read-only tmpfs. Landlock
/// already denies reading inside it, but not connecting to a unix socket there
/// (an agent socket in `~/.gnupg`, say): with the directory's entries hidden the
/// socket path no longer resolves. Fails closed.
pub(crate) unsafe fn hide_dirs(dirs: &[std::ffi::CString]) -> std::io::Result<()> {
    let opts = c"mode=000,size=4k";
    for d in dirs {
        if libc::mount(
            c"tmpfs".as_ptr(),
            d.as_ptr(),
            c"tmpfs".as_ptr(),
            libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            opts.as_ptr() as *const libc::c_void,
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Cover each of `files` (a socket, a fifo, a file in a read-denied directory)
/// with a bind of /dev/null, so a unix socket there no longer accepts a
/// connection. Not remounted read-only: in a user namespace that remount would
/// have to repeat /dev's locked flags (nosuid, noexec) or fail, and writing to
/// /dev/null loses nothing. Fails closed, like [`hide_dirs`].
pub(crate) unsafe fn hide_files(files: &[std::ffi::CString]) -> std::io::Result<()> {
    let null = c"/dev/null";
    for f in files {
        if libc::mount(null.as_ptr(), f.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Enter a new mount namespace whose tree is private, so nothing mounted in it
/// propagates to the host. Needs CAP_SYS_ADMIN (root, or a user namespace).
pub(crate) unsafe fn enter_private_mount_ns() -> std::io::Result<()> {
    if libc::unshare(libc::CLONE_NEWNS) != 0 {
        return Err(std::io::Error::last_os_error());
    }
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
    Ok(())
}

/// Mount a fresh, private tmpfs over `/dev/shm` inside the current mount namespace,
/// so the agent cannot use the host-shared POSIX shared-memory dir as a cross-
/// process/-container channel or fill it (a DoS). Called only inside a mount
/// namespace of our own. Fails closed: a requested
/// isolation that cannot be installed aborts the launch.
pub(crate) unsafe fn mount_private_shm() -> std::io::Result<()> {
    let shm = c"/dev/shm";
    // Only if /dev/shm exists as a dir (it does on normal Linux). If absent, there
    // is nothing shared to isolate.
    let mut st: libc::stat = std::mem::zeroed();
    if libc::stat(shm.as_ptr(), &mut st) != 0 || (st.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return Ok(());
    }
    let opts = c"mode=1777,size=64m";
    if libc::mount(
        c"tmpfs".as_ptr(),
        shm.as_ptr(),
        c"tmpfs".as_ptr(),
        0,
        opts.as_ptr() as *const libc::c_void,
    ) != 0
    {
        return Err(std::io::Error::last_os_error());
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

/// Drop ALL capabilities before exec when running as real root (adversarial
/// review #3). A uid-0 agent otherwise keeps CAP_SYS_MODULE (load a kernel module
/// = full escape), CAP_SYS_RAWIO, CAP_NET_RAW, CAP_SYS_PTRACE, CAP_SYS_ADMIN, …
/// Agent workloads (sh, git, node) need none. Order matters: drop the bounding set
/// and set SECBIT_NOROOT FIRST (these need CAP_SETPCAP), then zero the
/// effective/permitted/inheritable sets. No-op when euid != 0 (incl. inside a user
/// namespace, where host caps are already empty). Fails closed.
pub(crate) unsafe fn drop_all_capabilities() -> std::io::Result<()> {
    if libc::geteuid() != 0 {
        return Ok(());
    }
    // Drop the whole bounding set so no capability can be regained via a setuid
    // exec. Past CAP_LAST_CAP this returns EINVAL, which we ignore.
    for cap in 0..=63_i32 {
        let _ = libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0);
    }
    // SECBIT_NOROOT (+ locked): uid 0 no longer auto-grants caps on exec, and the
    // agent cannot undo it. Belt-and-suspenders with no_new_privs (set by seccomp).
    const SECBIT_NOROOT: libc::c_ulong = 1 << 0;
    const SECBIT_NOROOT_LOCKED: libc::c_ulong = 1 << 1;
    let _ = libc::prctl(
        libc::PR_SET_SECUREBITS,
        SECBIT_NOROOT | SECBIT_NOROOT_LOCKED,
        0,
        0,
        0,
    );
    // Finally zero the effective/permitted/inheritable sets (capability version 3
    // = two 32-bit words). Done LAST, since the steps above need CAP_SETPCAP.
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: libc::c_int,
    }
    #[repr(C)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    let hdr = CapHeader { version: LINUX_CAPABILITY_VERSION_3, pid: 0 };
    let data = [
        CapData { effective: 0, permitted: 0, inheritable: 0 },
        CapData { effective: 0, permitted: 0, inheritable: 0 },
    ];
    if libc::syscall(libc::SYS_capset, &hdr as *const _, data.as_ptr()) != 0 {
        return Err(std::io::Error::last_os_error());
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

/// `set_pdeathsig_kill` for the agent under our own PID 1 init: its parent IS
/// pid 1, so the reparenting check above would always fire. No race to cover
/// here either: if the init dies the kernel kills the whole namespace.
pub(crate) unsafe fn set_pdeathsig_kill_under_init() {
    libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong, 0, 0, 0);
}

/// Close every inherited fd >= 3 (keep stdio). Used by the init shim, which must
/// actually release std's exec-status pipe so the parent's spawn() unblocks.
pub(crate) unsafe fn close_inherited_fds() {
    let rc = libc::syscall(libc::SYS_close_range, 3u64, u32::MAX as u64, 0u64);
    if rc != 0 {
        for fd in 3..1024 {
            libc::close(fd);
        }
    }
}

/// Mark every inherited fd >= 3 close-on-exec, so an fd the orchestrator leaked
/// into the child does NOT survive into the exec'd agent (the FD-1 defense) —
/// WITHOUT close()ing them here. This matters just before exec in the agent:
/// close()ing std's exec-status pipe would make std abort when reporting a failed
/// exec; CLOEXEC leaves it usable for that report and still drops it on a
/// successful exec. `CLOSE_RANGE_CLOEXEC` (Linux 5.11+) is one syscall; fall back
/// to per-fd F_SETFD.
pub(crate) unsafe fn cloexec_inherited_fds() {
    const CLOSE_RANGE_CLOEXEC: u32 = 1 << 2;
    let rc = libc::syscall(
        libc::SYS_close_range,
        3u64,
        u32::MAX as u64,
        CLOSE_RANGE_CLOEXEC as u64,
    );
    if rc != 0 {
        for fd in 3..1024 {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            if flags >= 0 {
                let _ = libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
            }
        }
    }
}

