//! Shared `/proc` helpers for collectors (Linux). On other targets these return
//! empty, so collectors compile everywhere and simply observe nothing until a
//! platform-specific sibling is added.

/// (fd number, link target) for every open fd of `pid`.
#[cfg(target_os = "linux")]
pub fn fd_targets(pid: u32) -> Vec<(u32, String)> {
    let mut out = Vec::new();
    let dir = format!("/proc/{pid}/fd");
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            let fd = e
                .file_name()
                .to_string_lossy()
                .parse::<u32>()
                .unwrap_or(u32::MAX);
            if let Ok(target) = std::fs::read_link(e.path()) {
                out.push((fd, target.to_string_lossy().into_owned()));
            }
        }
    }
    out
}

/// (fd number, path) for every open fd of `pid` that is a real filesystem path
/// opened for WRITING (O_WRONLY or O_RDWR), read from `/proc/<pid>/fdinfo/<fd>`.
/// Sockets/pipes/anon inodes (whose link target is not an absolute path) are
/// skipped — this is the file axis, not the network axis.
#[cfg(target_os = "linux")]
pub fn write_fd_targets(pid: u32) -> Vec<(u32, String)> {
    let mut out = Vec::new();
    for (fd, target) in fd_targets(pid) {
        if !target.starts_with('/') {
            continue; // socket:[...], pipe:[...], anon_inode:... — not a file
        }
        // fdinfo `flags:` is octal; the low two bits are the access mode
        // (O_RDONLY=0, O_WRONLY=1, O_RDWR=2).
        if let Ok(info) = std::fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}")) {
            if let Some(accmode) = info
                .lines()
                .find_map(|l| l.strip_prefix("flags:"))
                .and_then(|v| u32::from_str_radix(v.trim(), 8).ok())
                .map(|flags| flags & 0o3)
            {
                if accmode == 1 || accmode == 2 {
                    out.push((fd, target));
                }
            }
        }
    }
    out
}

/// The executable backing `pid` (resolved `/proc/<pid>/exe`), if readable.
#[cfg(target_os = "linux")]
pub fn exe(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// `/proc/<pid>/cmdline`, NUL-separated args joined by spaces.
#[cfg(target_os = "linux")]
pub fn cmdline(pid: u32) -> Option<String> {
    std::fs::read(format!("/proc/{pid}/cmdline")).ok().map(|b| {
        b.split(|&c| c == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect::<Vec<_>>()
            .join(" ")
    })
}

/// All descendant pids of `root` (inclusive), walking `/proc/*/stat` ppid links.
#[cfg(target_os = "linux")]
pub fn process_tree(root: u32) -> Vec<u32> {
    use std::collections::{HashMap, HashSet, VecDeque};
    // build ppid -> children
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for e in entries.flatten() {
            let name = e.file_name();
            let pid = match name.to_string_lossy().parse::<u32>() {
                Ok(p) => p,
                Err(_) => continue,
            };
            if let Some(ppid) = ppid_of(pid) {
                children.entry(ppid).or_default().push(pid);
            }
        }
    }
    let mut out = HashSet::new();
    let mut q = VecDeque::from([root]);
    while let Some(p) = q.pop_front() {
        if out.insert(p) {
            if let Some(cs) = children.get(&p) {
                q.extend(cs);
            }
        }
    }
    out.into_iter().collect()
}

#[cfg(target_os = "linux")]
fn ppid_of(pid: u32) -> Option<u32> {
    // /proc/<pid>/stat: pid (comm) state ppid ...   comm may contain spaces/parens.
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close = stat.rfind(')')?;
    let rest = stat.get(close + 2..)?; // skip ") "
    let mut it = rest.split_whitespace();
    let _state = it.next()?;
    it.next()?.parse::<u32>().ok()
}

// --- macOS: no /proc, so observe via lsof / ps (sampling; misses <interval). ---

#[cfg(target_os = "macos")]
pub fn fd_targets(pid: u32) -> Vec<(u32, String)> {
    let out = match std::process::Command::new("lsof")
        .args(["-p", &pid.to_string(), "-F", "fn", "-w"])
        .output()
    {
        Ok(o) => o.stdout,
        Err(_) => return Vec::new(),
    };
    let mut res = Vec::new();
    let mut cur_fd: u32 = u32::MAX;
    for line in String::from_utf8_lossy(&out).lines() {
        if let Some(rest) = line.strip_prefix('f') {
            cur_fd = rest.parse().unwrap_or(u32::MAX);
        } else if let Some(name) = line.strip_prefix('n') {
            res.push((cur_fd, name.to_string()));
        }
    }
    res
}

/// macOS: write-mode file fds via `lsof -F fan` (a = access: r/w/u). Keep only
/// real paths opened for writing (w or u) — the file axis, not sockets.
#[cfg(target_os = "macos")]
pub fn write_fd_targets(pid: u32) -> Vec<(u32, String)> {
    let out = match std::process::Command::new("lsof")
        .args(["-p", &pid.to_string(), "-F", "fan", "-w"])
        .output()
    {
        Ok(o) => o.stdout,
        Err(_) => return Vec::new(),
    };
    let mut res = Vec::new();
    let mut cur_fd: u32 = u32::MAX;
    let mut writable = false;
    for line in String::from_utf8_lossy(&out).lines() {
        if let Some(rest) = line.strip_prefix('f') {
            cur_fd = rest.parse().unwrap_or(u32::MAX);
            writable = false;
        } else if let Some(acc) = line.strip_prefix('a') {
            // lsof access field: r, w, or u (read+write).
            writable = acc.contains('w') || acc.contains('u');
        } else if let Some(name) = line.strip_prefix('n') {
            if writable && name.starts_with('/') {
                res.push((cur_fd, name.to_string()));
            }
        }
    }
    res
}

#[cfg(target_os = "macos")]
pub fn exe(pid: u32) -> Option<String> {
    let out = std::process::Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "comm="])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

#[cfg(target_os = "macos")]
pub fn cmdline(pid: u32) -> Option<String> {
    let out = std::process::Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "command="])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

#[cfg(target_os = "macos")]
pub fn process_tree(root: u32) -> Vec<u32> {
    use std::collections::{HashMap, HashSet, VecDeque};
    let out = match std::process::Command::new("ps").args(["-axo", "pid=,ppid="]).output() {
        Ok(o) => o.stdout,
        Err(_) => return vec![root],
    };
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for line in String::from_utf8_lossy(&out).lines() {
        let mut it = line.split_whitespace();
        if let (Some(p), Some(pp)) = (it.next(), it.next()) {
            if let (Ok(p), Ok(pp)) = (p.parse::<u32>(), pp.parse::<u32>()) {
                children.entry(pp).or_default().push(p);
            }
        }
    }
    let mut out = HashSet::new();
    let mut q = VecDeque::from([root]);
    while let Some(p) = q.pop_front() {
        if out.insert(p) {
            if let Some(cs) = children.get(&p) {
                q.extend(cs);
            }
        }
    }
    out.into_iter().collect()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn fd_targets(_pid: u32) -> Vec<(u32, String)> {
    Vec::new()
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn write_fd_targets(_pid: u32) -> Vec<(u32, String)> {
    Vec::new()
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn exe(_pid: u32) -> Option<String> {
    None
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn cmdline(_pid: u32) -> Option<String> {
    None
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn process_tree(root: u32) -> Vec<u32> {
    vec![root]
}
