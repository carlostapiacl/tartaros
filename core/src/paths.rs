//! Path resolution shared by the policy and the backends.

use std::path::Path;
use std::path::PathBuf;

/// Resolve a path's symlinks the way the kernel would when the path is used,
/// including links whose target does not exist yet (a write through a dangling
/// link creates the target, so a rule on the link must land on the target).
/// Walks component by component: each existing symlink is replaced by its
/// target (relative targets resolve from the link's directory, and a `..` in a
/// target is taken from where the previous link led), while missing components
/// are appended as written. Bounded to 40 link hops, like the kernel.
pub fn resolve_best_effort(path: &Path) -> PathBuf {
    use std::collections::VecDeque;
    use std::path::Component;
    // The prefix and root of an absolute path (`/` on Unix; `C:\`, `\\server\share\`
    // or `\\?\C:\` on Windows). Starting from a bare `/` would drop the drive, and
    // `/Users\x` is not absolute on Windows: resolving it again would land under
    // the current directory.
    let anchor = |p: &Path| -> PathBuf {
        p.components()
            .take_while(|c| matches!(c, Component::Prefix(_) | Component::RootDir))
            .collect()
    };
    let mut out = if path.is_absolute() {
        anchor(path)
    } else {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"))
    };
    let mut pending: VecDeque<std::ffi::OsString> = VecDeque::new();
    let push_all = |p: &Path, q: &mut VecDeque<std::ffi::OsString>, front: bool| {
        let comps: Vec<std::ffi::OsString> = p
            .components()
            .filter_map(|c| match c {
                Component::Normal(n) => Some(n.to_owned()),
                Component::ParentDir => Some("..".into()),
                _ => None,
            })
            .collect();
        if front {
            for c in comps.into_iter().rev() {
                q.push_front(c);
            }
        } else {
            q.extend(comps);
        }
    };
    push_all(path, &mut pending, false);
    let mut hops = 0;
    while let Some(c) = pending.pop_front() {
        if c == ".." {
            out.pop();
            continue;
        }
        let cand = out.join(&c);
        match std::fs::symlink_metadata(&cand) {
            Ok(m) if m.file_type().is_symlink() && hops < 40 => {
                hops += 1;
                match std::fs::read_link(&cand) {
                    Ok(target) => {
                        if target.is_absolute() {
                            out = anchor(&target);
                        }
                        push_all(&target, &mut pending, true);
                    }
                    Err(_) => out = cand,
                }
            }
            _ => out = cand,
        }
    }
    out
}
