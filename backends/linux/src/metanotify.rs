//! Metadata changes outside the territory, without a mount namespace.
//!
//! Landlock has no access right for chmod, chown, utimes or extended attributes,
//! so with only the carve an agent can `chmod 0777` a tool outside its roots,
//! forge the mtime of a log, or set an xattr on a user file. With a mount
//! namespace everything outside the roots is remounted read-only and the kernel
//! refuses these; without one (a non-root user on Ubuntu 23.10+), this module
//! closes them.
//!
//! A seccomp filter in the child sends those syscalls to the supervisor
//! (`SECCOMP_RET_USER_NOTIF`). For each one the supervisor reads the path from
//! the process's memory, opens the object it names with `O_PATH` from the
//! process's own cwd or dirfd, and checks the real path of what it opened
//! against the write grants Landlock was given. Allowed, it performs the change
//! itself on that descriptor; otherwise it answers EACCES. The syscall is never
//! continued in the agent (`SECCOMP_USER_NOTIF_FLAG_CONTINUE` would let the
//! agent swap the path after the check): what was checked is what is changed.
//! The serving thread drops its capabilities first, so a root agent without
//! capabilities gets no more from the supervisor than it would from the kernel.
//!
//! Reading another process's memory needs ptrace access: with Yama
//! `ptrace_scope=1` (the Ubuntu default) the supervisor reaches its
//! descendants, which is every process of the run unless one is reparented
//! outside it; such a process's metadata calls fail with EACCES (closed).

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};

const FCHMODAT2: i64 = 452;
const SETXATTRAT: i64 = 463;
const REMOVEXATTRAT: i64 = 466;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xC000_003E; // AUDIT_ARCH_X86_64
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xC000_00B7; // AUDIT_ARCH_AARCH64

/// The syscalls sent to the supervisor.
fn trapped() -> Vec<i64> {
    #[allow(unused_mut)]
    let mut v = vec![
        libc::SYS_fchmodat,
        FCHMODAT2,
        libc::SYS_fchownat,
        libc::SYS_utimensat,
        libc::SYS_fchmod,
        libc::SYS_fchown,
        libc::SYS_setxattr,
        libc::SYS_lsetxattr,
        libc::SYS_fsetxattr,
        libc::SYS_removexattr,
        libc::SYS_lremovexattr,
        libc::SYS_fremovexattr,
        SETXATTRAT,
        REMOVEXATTRAT,
    ];
    #[cfg(target_arch = "x86_64")]
    v.extend([
        libc::SYS_chmod,
        libc::SYS_chown,
        libc::SYS_lchown,
        libc::SYS_utime,
        libc::SYS_utimes,
        libc::SYS_futimesat,
    ]);
    v
}

/// The filter, built in the parent (no allocation after fork).
pub(crate) struct Filter(Vec<libc::sock_filter>);

pub(crate) fn compile() -> Filter {
    const LD: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    const JEQ: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
    const JGE: u16 = (libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K) as u16;
    const RET: u16 = (libc::BPF_RET | libc::BPF_K) as u16;
    let ins = |code: u16, jt: u8, jf: u8, k: u32| libc::sock_filter { code, jt, jf, k };
    let eperm = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
    let mut p = vec![
        ins(LD, 0, 0, 4), // seccomp_data.arch
        ins(JEQ, 1, 0, AUDIT_ARCH),
        ins(RET, 0, 0, eperm), // another ABI (i386 on x86_64): not served, closed
        ins(LD, 0, 0, 0), // seccomp_data.nr
        ins(JGE, 0, 1, 0x4000_0000),
        ins(RET, 0, 0, eperm), // x32
    ];
    for nr in trapped() {
        p.push(ins(JEQ, 0, 1, nr as u32));
        p.push(ins(RET, 0, 0, libc::SECCOMP_RET_USER_NOTIF));
    }
    p.push(ins(RET, 0, 0, libc::SECCOMP_RET_ALLOW));
    Filter(p)
}

/// The two ends of the socket the child hands its listener over.
pub(crate) struct Channel {
    pub(crate) parent: OwnedFd,
    pub(crate) child: OwnedFd,
}

pub(crate) fn channel() -> std::io::Result<Channel> {
    let mut sv = [0; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0, sv.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { Channel { parent: OwnedFd::from_raw_fd(sv[0]), child: OwnedFd::from_raw_fd(sv[1]) } })
}

/// In the child, after no_new_privs: install the filter and send its listener
/// to the parent, then close it here (the agent must never hold it).
/// Async-signal-safe: syscalls on memory built before the fork.
pub(crate) unsafe fn install_in_child(f: &Filter, sock: RawFd) -> std::io::Result<()> {
    let prog = libc::sock_fprog { len: f.0.len() as u16, filter: f.0.as_ptr() as *mut libc::sock_filter };
    let listener = libc::syscall(
        libc::SYS_seccomp,
        libc::SECCOMP_SET_MODE_FILTER,
        libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
        &prog as *const libc::sock_fprog,
    ) as RawFd;
    if listener < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec { iov_base: byte.as_mut_ptr() as *mut libc::c_void, iov_len: 1 };
    let mut cbuf = [0u64; 4]; // CMSG_SPACE(sizeof(int)) = 24 on 64-bit, 8-aligned
    let mut msg: libc::msghdr = std::mem::zeroed();
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as _;
    let c = libc::CMSG_FIRSTHDR(&msg);
    (*c).cmsg_level = libc::SOL_SOCKET;
    (*c).cmsg_type = libc::SCM_RIGHTS;
    (*c).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
    *(libc::CMSG_DATA(c) as *mut RawFd) = listener;
    let sent = libc::sendmsg(sock, &msg, 0);
    let e = std::io::Error::last_os_error();
    libc::close(listener);
    libc::close(sock);
    if sent < 0 {
        return Err(e);
    }
    Ok(())
}

/// In the parent: wait for the listener on a thread and serve it until every
/// process of the run is gone. `grants` are the run's Landlock write grants.
pub(crate) fn serve(parent: OwnedFd, grants: Vec<PathBuf>) {
    let _ = std::thread::Builder::new().name("tartaros-meta".into()).spawn(move || {
        drop_thread_capabilities();
        let Some(listener) = receive(&parent) else { return };
        drop(parent);
        let s = Server { grants };
        loop {
            let mut pfd = libc::pollfd { fd: listener.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            let n = unsafe { libc::poll(&mut pfd, 1, -1) };
            if n < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return;
            }
            if pfd.revents & libc::POLLIN == 0 {
                return; // POLLHUP: no process of the run is left
            }
            let mut req: libc::seccomp_notif = unsafe { std::mem::zeroed() };
            if unsafe { libc::ioctl(listener.as_raw_fd(), libc::SECCOMP_IOCTL_NOTIF_RECV, &mut req) } != 0 {
                continue; // the caller died before we read it (ENOENT), or EINTR
            }
            let error = s.handle(listener.as_raw_fd(), &req);
            let mut resp = libc::seccomp_notif_resp { id: req.id, val: 0, error, flags: 0 };
            unsafe { libc::ioctl(listener.as_raw_fd(), libc::SECCOMP_IOCTL_NOTIF_SEND, &mut resp) };
        }
    });
}

fn receive(sock: &OwnedFd) -> Option<OwnedFd> {
    unsafe {
        let mut byte = [0u8; 1];
        let mut iov = libc::iovec { iov_base: byte.as_mut_ptr() as *mut libc::c_void, iov_len: 1 };
        let mut cbuf = [0u64; 4];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = std::mem::size_of_val(&cbuf) as _;
        if libc::recvmsg(sock.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) <= 0 {
            return None;
        }
        let c = libc::CMSG_FIRSTHDR(&msg);
        if c.is_null() || (*c).cmsg_type != libc::SCM_RIGHTS {
            return None;
        }
        Some(OwnedFd::from_raw_fd(*(libc::CMSG_DATA(c) as *const RawFd)))
    }
}

/// Capabilities are per thread: this one serves with none in its effective set.
fn drop_thread_capabilities() {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let mut h = Header { version: 0x2008_0522, pid: 0 }; // _LINUX_CAPABILITY_VERSION_3
    let mut d = [Data { effective: 0, permitted: 0, inheritable: 0 }; 2];
    unsafe {
        if libc::syscall(libc::SYS_capget, &mut h, d.as_mut_ptr()) == 0 {
            for x in &mut d {
                x.effective = 0;
            }
            libc::syscall(libc::SYS_capset, &mut h, d.as_ptr());
        }
    }
}

struct Server {
    grants: Vec<PathBuf>,
}

/// What a syscall asks for, once decoded.
enum Op {
    Mode(u32),
    Owner(u32, u32),
    Times(Option<[libc::timespec; 2]>),
    SetXattr(CString, Vec<u8>, i32),
    RemoveXattr(CString),
    NotServed,
}

/// Where the object is: a path from a directory fd (or the cwd), or an fd.
enum Target {
    Path { dirfd: i64, path_ptr: u64, follow: bool, empty_ok: bool },
    Fd(i64),
}

const AT_FDCWD: i64 = libc::AT_FDCWD as i64;

impl Server {
    /// The errno to answer (0 for success), negated as the kernel wants it.
    fn handle(&self, listener: RawFd, req: &libc::seccomp_notif) -> i32 {
        match self.serve_one(listener, req) {
            Ok(()) => 0,
            Err(e) => -e,
        }
    }

    fn serve_one(&self, listener: RawFd, req: &libc::seccomp_notif) -> Result<(), i32> {
        let a = req.data.args;
        let nr = req.data.nr as i64;
        let mem = Mem::open(req.pid)?;
        let nofollow = |flags: u64| flags & libc::AT_SYMLINK_NOFOLLOW as u64 != 0;
        let empty = |flags: u64| flags & libc::AT_EMPTY_PATH as u64 != 0;
        let path = |dirfd: i64, ptr: u64, follow: bool, empty_ok: bool| Target::Path { dirfd, path_ptr: ptr, follow, empty_ok };
        let (target, op) = match nr {
            n if n == libc::SYS_fchmodat => (path(a[0] as i32 as i64, a[1], true, false), Op::Mode(a[2] as u32)),
            FCHMODAT2 => (path(a[0] as i32 as i64, a[1], !nofollow(a[3]), empty(a[3])), Op::Mode(a[2] as u32)),
            n if n == libc::SYS_fchownat => (path(a[0] as i32 as i64, a[1], !nofollow(a[4]), empty(a[4])), Op::Owner(a[2] as u32, a[3] as u32)),
            n if n == libc::SYS_fchmod => (Target::Fd(a[0] as i32 as i64), Op::Mode(a[1] as u32)),
            n if n == libc::SYS_fchown => (Target::Fd(a[0] as i32 as i64), Op::Owner(a[1] as u32, a[2] as u32)),
            n if n == libc::SYS_utimensat => {
                let times = if a[2] == 0 { None } else { Some(mem.timespecs(a[2])?) };
                let t = if a[1] == 0 { Target::Fd(a[0] as i32 as i64) } else { path(a[0] as i32 as i64, a[1], !nofollow(a[3]), false) };
                (t, Op::Times(times))
            }
            n if n == libc::SYS_setxattr || n == libc::SYS_lsetxattr => {
                let name = mem.string(a[1])?;
                let value = mem.bytes(a[2], a[3] as usize)?;
                (path(AT_FDCWD, a[0], n == libc::SYS_setxattr, false), Op::SetXattr(name, value, a[4] as i32))
            }
            n if n == libc::SYS_fsetxattr => {
                let name = mem.string(a[1])?;
                let value = mem.bytes(a[2], a[3] as usize)?;
                (Target::Fd(a[0] as i32 as i64), Op::SetXattr(name, value, a[4] as i32))
            }
            n if n == libc::SYS_removexattr || n == libc::SYS_lremovexattr => {
                (path(AT_FDCWD, a[0], n == libc::SYS_removexattr, false), Op::RemoveXattr(mem.string(a[1])?))
            }
            n if n == libc::SYS_fremovexattr => (Target::Fd(a[0] as i32 as i64), Op::RemoveXattr(mem.string(a[1])?)),
            #[cfg(target_arch = "x86_64")]
            n if n == libc::SYS_chmod => (path(AT_FDCWD, a[0], true, false), Op::Mode(a[1] as u32)),
            #[cfg(target_arch = "x86_64")]
            n if n == libc::SYS_chown || n == libc::SYS_lchown => {
                (path(AT_FDCWD, a[0], n == libc::SYS_chown, false), Op::Owner(a[1] as u32, a[2] as u32))
            }
            #[cfg(target_arch = "x86_64")]
            n if n == libc::SYS_utime => {
                let times = if a[1] == 0 { None } else { Some(mem.utimbuf(a[1])?) };
                (path(AT_FDCWD, a[0], true, false), Op::Times(times))
            }
            #[cfg(target_arch = "x86_64")]
            n if n == libc::SYS_utimes || n == libc::SYS_futimesat => {
                let (dirfd, p, t) = if n == libc::SYS_utimes { (AT_FDCWD, a[0], a[1]) } else { (a[0] as i32 as i64, a[1], a[2]) };
                let times = if t == 0 { None } else { Some(mem.timevals(t)?) };
                (path(dirfd, p, true, false), Op::Times(times))
            }
            _ => (Target::Fd(-1), Op::NotServed),
        };
        if matches!(op, Op::NotServed) {
            return Err(libc::ENOSYS); // setxattrat & co: callers fall back to the older calls
        }
        let obj = self.open_target(req.pid, &mem, target)?;
        // The pid could have been reused while we read its memory.
        let mut id = req.id;
        if unsafe { libc::ioctl(listener, libc::SECCOMP_IOCTL_NOTIF_ID_VALID, &mut id) } != 0 {
            return Err(libc::ENOENT);
        }
        let real = std::fs::read_link(format!("/proc/self/fd/{}", obj.as_raw_fd())).map_err(|_| libc::EACCES)?;
        if !self.writable(&real) {
            return Err(libc::EACCES);
        }
        apply(&obj, op)
    }

    /// May the run write `real`? Under one of Landlock's write grants (or /dev,
    /// which every run is granted). An object with no path (a pipe, a socket)
    /// has no metadata the territory protects.
    fn writable(&self, real: &Path) -> bool {
        let s = real.to_string_lossy();
        if !s.starts_with('/') {
            return true; // pipe:[…], socket:[…], anon_inode:…
        }
        // An unlinked file (an O_TMPFILE, or one removed while open) is judged by its directory.
        let real = match s.strip_suffix(" (deleted)") {
            Some(p) => Path::new(p).parent().map(Path::to_path_buf).unwrap_or_default(),
            None => real.to_path_buf(),
        };
        real.starts_with("/dev") || self.grants.iter().any(|g| real.starts_with(g))
    }

    fn open_target(&self, pid: u32, mem: &Mem, t: Target) -> Result<OwnedFd, i32> {
        match t {
            Target::Fd(fd) if fd >= 0 => open_path(&format!("/proc/{pid}/fd/{fd}"), true),
            Target::Fd(_) => Err(libc::EBADF),
            Target::Path { dirfd, path_ptr, follow, empty_ok } => {
                let p = mem.string(path_ptr)?;
                if p.as_bytes().is_empty() {
                    if !empty_ok {
                        return Err(libc::ENOENT);
                    }
                    return if dirfd == AT_FDCWD { open_path(&format!("/proc/{pid}/cwd"), true) } else { self.open_target(pid, mem, Target::Fd(dirfd)) };
                }
                let base = if p.as_bytes()[0] == b'/' {
                    None
                } else if dirfd == AT_FDCWD {
                    Some(open_path(&format!("/proc/{pid}/cwd"), true)?)
                } else {
                    Some(open_path(&format!("/proc/{pid}/fd/{dirfd}"), true)?)
                };
                let flags = libc::O_PATH | libc::O_CLOEXEC | if follow { 0 } else { libc::O_NOFOLLOW };
                let fd = unsafe { libc::openat(base.as_ref().map_or(libc::AT_FDCWD, |b| b.as_raw_fd()), p.as_ptr(), flags) };
                if fd < 0 {
                    return Err(errno());
                }
                Ok(unsafe { OwnedFd::from_raw_fd(fd) })
            }
        }
    }
}

fn open_path(p: &str, follow: bool) -> Result<OwnedFd, i32> {
    let c = CString::new(p).map_err(|_| libc::EINVAL)?;
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC | if follow { 0 } else { libc::O_NOFOLLOW }) };
    if fd < 0 {
        return Err(errno());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO)
}

fn is_symlink(fd: &OwnedFd) -> bool {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    unsafe { libc::fstatat(fd.as_raw_fd(), c"".as_ptr(), &mut st, libc::AT_EMPTY_PATH) == 0 && st.st_mode & libc::S_IFMT == libc::S_IFLNK }
}

/// Perform the change on the object that was checked, through its descriptor.
fn apply(obj: &OwnedFd, op: Op) -> Result<(), i32> {
    let proc_path = CString::new(format!("/proc/self/fd/{}", obj.as_raw_fd())).map_err(|_| libc::EINVAL)?;
    let link = is_symlink(obj);
    let r = unsafe {
        match op {
            // Linux has no mode, times or user xattrs on a symlink itself.
            Op::Mode(_) | Op::Times(_) | Op::SetXattr(..) | Op::RemoveXattr(_) if link => return Err(libc::EOPNOTSUPP),
            Op::Mode(m) => libc::chmod(proc_path.as_ptr(), m as libc::mode_t),
            Op::Owner(u, g) => libc::fchownat(obj.as_raw_fd(), c"".as_ptr(), u, g, libc::AT_EMPTY_PATH),
            Op::Times(t) => {
                let ptr = t.as_ref().map_or(std::ptr::null(), |t| t.as_ptr());
                libc::utimensat(libc::AT_FDCWD, proc_path.as_ptr(), ptr, 0)
            }
            Op::SetXattr(name, value, flags) => {
                libc::setxattr(proc_path.as_ptr(), name.as_ptr(), value.as_ptr() as *const libc::c_void, value.len(), flags)
            }
            Op::RemoveXattr(name) => libc::removexattr(proc_path.as_ptr(), name.as_ptr()),
            Op::NotServed => return Err(libc::ENOSYS),
        }
    };
    if r != 0 {
        return Err(errno());
    }
    Ok(())
}

/// The calling process's memory, for the arguments its pointers name.
struct Mem(std::fs::File);

impl Mem {
    fn open(pid: u32) -> Result<Self, i32> {
        std::fs::File::open(format!("/proc/{pid}/mem")).map(Mem).map_err(|_| libc::EACCES)
    }

    fn bytes(&self, addr: u64, len: usize) -> Result<Vec<u8>, i32> {
        use std::os::unix::fs::FileExt;
        if len > 64 * 1024 {
            return Err(libc::E2BIG); // XATTR_SIZE_MAX
        }
        let mut b = vec![0u8; len];
        self.0.read_exact_at(&mut b, addr).map_err(|_| libc::EFAULT)?;
        Ok(b)
    }

    /// A NUL-terminated string, up to PATH_MAX.
    fn string(&self, addr: u64) -> Result<CString, i32> {
        use std::os::unix::fs::FileExt;
        let mut out = Vec::new();
        let mut chunk = [0u8; 256];
        while out.len() < libc::PATH_MAX as usize {
            let n = self.0.read_at(&mut chunk, addr + out.len() as u64).map_err(|_| libc::EFAULT)?;
            if n == 0 {
                return Err(libc::EFAULT);
            }
            if let Some(z) = chunk[..n].iter().position(|b| *b == 0) {
                out.extend_from_slice(&chunk[..z]);
                return CString::new(out).map_err(|_| libc::EINVAL);
            }
            out.extend_from_slice(&chunk[..n]);
        }
        Err(libc::ENAMETOOLONG)
    }

    fn words(&self, addr: u64) -> Result<[i64; 4], i32> {
        let b = self.bytes(addr, 32)?;
        let w = |i: usize| i64::from_ne_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
        Ok([w(0), w(1), w(2), w(3)])
    }

    fn timespecs(&self, addr: u64) -> Result<[libc::timespec; 2], i32> {
        let w = self.words(addr)?;
        Ok([libc::timespec { tv_sec: w[0], tv_nsec: w[1] }, libc::timespec { tv_sec: w[2], tv_nsec: w[3] }])
    }

    #[cfg(target_arch = "x86_64")]
    fn timevals(&self, addr: u64) -> Result<[libc::timespec; 2], i32> {
        let w = self.words(addr)?;
        Ok([libc::timespec { tv_sec: w[0], tv_nsec: w[1] * 1000 }, libc::timespec { tv_sec: w[2], tv_nsec: w[3] * 1000 }])
    }

    #[cfg(target_arch = "x86_64")]
    fn utimbuf(&self, addr: u64) -> Result<[libc::timespec; 2], i32> {
        let b = self.bytes(addr, 16)?;
        let w = |i: usize| i64::from_ne_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
        Ok([libc::timespec { tv_sec: w(0), tv_nsec: 0 }, libc::timespec { tv_sec: w(1), tv_nsec: 0 }])
    }
}
