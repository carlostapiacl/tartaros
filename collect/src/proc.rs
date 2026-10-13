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

#[cfg(not(target_os = "linux"))]
pub fn fd_targets(_pid: u32) -> Vec<(u32, String)> {
    Vec::new()
}
#[cfg(not(target_os = "linux"))]
pub fn exe(_pid: u32) -> Option<String> {
    None
}
#[cfg(not(target_os = "linux"))]
pub fn cmdline(_pid: u32) -> Option<String> {
    None
}
#[cfg(not(target_os = "linux"))]
pub fn process_tree(root: u32) -> Vec<u32> {
    vec![root]
}
