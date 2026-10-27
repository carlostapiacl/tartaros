//! `--snapshot`: the writable roots as they were before the run, and
//! `tartaros rollback ID` to put them back.
//!
//! A snapshot is a manifest (every directory, file and symlink under each root:
//! mode, size, sha256 or link target) plus the files' contents, stored once by
//! hash in `<state>/snapshots/objects`, so a second snapshot of the same tree
//! copies only what changed. The store lives outside the writable roots (a run
//! whose store would fall inside one is refused) and is read-denied for the run,
//! so the agent can neither alter a snapshot nor read through it what a
//! read-deny inside a root hides. Read-denied paths and `--snapshot-exclude`
//! names are not snapshotted, and rollback leaves them as they are.
//!
//! Rollback first snapshots the current state (so a rollback can itself be
//! rolled back), then makes each root match the manifest: entries added since
//! are removed, changed ones restored, removed ones re-created. It works from
//! the shallowest path down and never writes through a symlink: a directory the
//! agent replaced with a link is removed and re-created first, and files are
//! written to a temporary name and renamed into place. Run it after the run's
//! processes are gone.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

pub const DEFAULT_MAX_BYTES: u64 = 2 << 30;

/// What `run --snapshot` was asked for.
#[derive(Debug, Clone, Default)]
pub struct Spec {
    pub on: bool,
    pub exclude: Vec<String>,
    pub max_bytes: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Entry {
    Dir { mode: u32 },
    File { mode: u32, size: u64, sha256: String },
    Link { target: String },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Root {
    pub path: PathBuf,
    /// Relative path (`/`-separated) → entry. The root itself is not listed.
    pub entries: BTreeMap<String, Entry>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Manifest {
    pub id: String,
    pub created_unix: u64,
    pub exclude: Vec<String>,
    /// Absolute paths not snapshotted and left alone (read-denied).
    pub skipped: Vec<PathBuf>,
    pub roots: Vec<Root>,
}

/// `$TARTAROS_STATE_DIR`, else `$XDG_STATE_HOME/tartaros`, else `~/.local/state/tartaros`.
pub fn state_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("TARTAROS_STATE_DIR") {
        return PathBuf::from(d);
    }
    if let Some(d) = std::env::var_os("XDG_STATE_HOME") {
        return PathBuf::from(d).join("tartaros");
    }
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).unwrap_or_default();
    PathBuf::from(home).join(".local/state/tartaros")
}

pub fn store() -> PathBuf {
    state_dir().join("snapshots")
}

fn objects() -> PathBuf {
    store().join("objects")
}

fn object(sha: &str) -> PathBuf {
    objects().join(&sha[..2]).join(sha)
}

fn mkdir_private(d: &Path) -> io::Result<()> {
    fs::create_dir_all(d)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(d, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

#[cfg(unix)]
fn mode_of(m: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    m.permissions().mode() & 0o7777
}
#[cfg(not(unix))]
fn mode_of(m: &fs::Metadata) -> u32 {
    if m.permissions().readonly() { 0o444 } else { 0o644 }
}

fn set_mode(p: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(p, fs::Permissions::from_mode(mode));
    }
    #[cfg(not(unix))]
    {
        if let Ok(m) = fs::metadata(p) {
            let mut perm = m.permissions();
            perm.set_readonly(mode & 0o222 == 0);
            let _ = fs::set_permissions(p, perm);
        }
    }
}

fn sha256_file(p: &Path) -> io::Result<String> {
    let mut f = fs::File::open(p)?;
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n]);
    }
    Ok(ctx.finish().as_ref().iter().map(|b| format!("{b:02x}")).collect())
}

/// The tree under `root`, without following links. `skip` says which paths
/// (read-denied, the store) and names (excluded) are left out.
fn walk(root: &Path, exclude: &[String], skip: &[PathBuf]) -> io::Result<BTreeMap<String, (PathBuf, fs::Metadata)>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in fs::read_dir(&dir)? {
            let e = e?;
            let path = e.path();
            if exclude.iter().any(|x| e.file_name().to_string_lossy() == *x) || skip.iter().any(|s| path.starts_with(s)) {
                continue;
            }
            let m = fs::symlink_metadata(&path)?;
            let rel = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().replace('\\', "/");
            if m.is_dir() {
                stack.push(path.clone());
            } else if !m.is_file() && !m.file_type().is_symlink() {
                continue; // sockets, fifos, devices: nothing to restore
            }
            out.insert(rel, (path, m));
        }
    }
    Ok(out)
}

fn entry_of(path: &Path, m: &fs::Metadata) -> io::Result<Entry> {
    Ok(if m.file_type().is_symlink() {
        Entry::Link { target: fs::read_link(path)?.to_string_lossy().into_owned() }
    } else if m.is_dir() {
        Entry::Dir { mode: mode_of(m) }
    } else {
        Entry::File { mode: mode_of(m), size: m.len(), sha256: sha256_file(path)? }
    })
}

fn store_object(path: &Path, sha: &str) -> io::Result<()> {
    let dst = object(sha);
    if dst.exists() {
        return Ok(());
    }
    mkdir_private(dst.parent().unwrap())?;
    let tmp = dst.with_extension(format!("tmp{}", std::process::id()));
    fs::copy(path, &tmp)?; // a clone on APFS, a reflink where the filesystem has them
    set_mode(&tmp, 0o400);
    // The file could have changed between hashing and copying: store only what hashes right.
    if sha256_file(&tmp)? != sha {
        let _ = fs::remove_file(&tmp);
        return Err(io::Error::other(format!("{} changed while it was snapshotted", path.display())));
    }
    fs::rename(&tmp, &dst)
}

fn new_id() -> (String, u64) {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    (format!("{}-{:x}", stamp(now.as_secs()).replace([':', '-'], ""), std::process::id()), now.as_secs())
}

/// `2026-10-26T23:15:00Z` from Unix seconds (civil-from-days).
pub fn stamp(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let s = secs % 86400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", s / 3600, s % 3600 / 60, s % 60)
}

/// Snapshot `roots`. Refused (Err) past `max_bytes`, before anything is copied.
pub fn take(roots: &[PathBuf], exclude: &[String], skipped: &[PathBuf], max_bytes: u64) -> Result<Manifest, String> {
    let st = store();
    let mut skip: Vec<PathBuf> = skipped.to_vec();
    skip.push(st.clone());
    let mut trees = Vec::new();
    let mut total = 0u64;
    for r in roots {
        let t = walk(r, exclude, &skip).map_err(|e| format!("snapshot: reading {}: {e}", r.display()))?;
        total += t.values().filter(|(_, m)| m.is_file()).map(|(_, m)| m.len()).sum::<u64>();
        trees.push((r.clone(), t));
    }
    if total > max_bytes {
        return Err(format!(
            "snapshot: the writable roots hold {} MiB, over --snapshot-max-bytes ({} MiB); exclude what can be rebuilt (--snapshot-exclude node_modules) or raise the limit",
            total >> 20,
            max_bytes >> 20
        ));
    }
    mkdir_private(&objects()).map_err(|e| format!("snapshot: {}: {e}", objects().display()))?;
    let (id, created_unix) = new_id();
    let mut out = Vec::new();
    for (root, tree) in trees {
        let mut entries = BTreeMap::new();
        for (rel, (path, m)) in tree {
            let e = entry_of(&path, &m).map_err(|e| format!("snapshot: {}: {e}", path.display()))?;
            if let Entry::File { sha256, .. } = &e {
                store_object(&path, sha256).map_err(|e| format!("snapshot: {}: {e}", path.display()))?;
            }
            entries.insert(rel, e);
        }
        out.push(Root { path: root, entries });
    }
    let m = Manifest { id: id.clone(), created_unix, exclude: exclude.to_vec(), skipped: skipped.to_vec(), roots: out };
    let json = serde_json::to_vec_pretty(&m).map_err(|e| e.to_string())?;
    let path = st.join(format!("{id}.json"));
    let tmp = path.with_extension("json.tmp");
    fs::File::create(&tmp).and_then(|mut f| f.write_all(&json)).and_then(|_| fs::rename(&tmp, &path)).map_err(|e| format!("snapshot: {}: {e}", path.display()))?;
    Ok(m)
}

pub fn load(id: &str) -> Result<Manifest, String> {
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(format!("no snapshot {id:?}"));
    }
    let p = store().join(format!("{id}.json"));
    let b = fs::read(&p).map_err(|_| format!("no snapshot {id} in {}", store().display()))?;
    serde_json::from_slice(&b).map_err(|e| format!("snapshot {id}: {e}"))
}

pub fn list() -> Vec<Manifest> {
    let mut v: Vec<Manifest> = fs::read_dir(store())
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.strip_suffix(".json").map(str::to_string))
        .filter_map(|id| load(&id).ok())
        .collect();
    v.sort_by_key(|m| m.created_unix);
    v
}

/// How the roots differ from a snapshot: (added, changed, removed), relative to each root.
#[derive(Debug, Default)]
pub struct Diff {
    pub added: Vec<PathBuf>,
    pub changed: Vec<PathBuf>,
    pub removed: Vec<PathBuf>,
}

pub fn diff(m: &Manifest) -> Result<Diff, String> {
    let mut d = Diff::default();
    let mut skip = m.skipped.clone();
    skip.push(store());
    for r in &m.roots {
        let now = walk(&r.path, &m.exclude, &skip).map_err(|e| format!("{}: {e}", r.path.display()))?;
        for (rel, (path, meta)) in &now {
            match r.entries.get(rel) {
                None => d.added.push(path.clone()),
                Some(was) => {
                    if !same(was, path, meta) {
                        d.changed.push(path.clone());
                    }
                }
            }
        }
        for rel in r.entries.keys().filter(|k| !now.contains_key(*k)) {
            d.removed.push(r.path.join(rel));
        }
    }
    Ok(d)
}

fn same(was: &Entry, path: &Path, m: &fs::Metadata) -> bool {
    match was {
        Entry::Dir { mode } => m.is_dir() && mode_of(m) == *mode,
        Entry::Link { target } => m.file_type().is_symlink() && fs::read_link(path).is_ok_and(|t| t.to_string_lossy() == *target),
        Entry::File { mode, size, sha256 } => {
            m.is_file() && m.len() == *size && mode_of(m) == *mode && sha256_file(path).is_ok_and(|s| s == *sha256)
        }
    }
}

/// Remove whatever is at `p` (not following a link); a directory only when
/// empty, so nothing the snapshot left out (excluded, read-denied) is lost.
fn remove_entry(p: &Path) -> io::Result<()> {
    match fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => fs::remove_dir(p),
        Ok(_) => fs::remove_file(p),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Make the roots match `m`. Returns the id of the snapshot of the state it
/// replaced, and the paths it could not restore.
pub fn rollback(m: &Manifest, dry_run: bool) -> Result<(Option<String>, Diff, Vec<String>), String> {
    let d = diff(m)?;
    if dry_run {
        return Ok((None, d, Vec::new()));
    }
    let roots: Vec<PathBuf> = m.roots.iter().map(|r| r.path.clone()).collect();
    let before = take(&roots, &m.exclude, &m.skipped, u64::MAX)?;
    let mut failed = Vec::new();
    let mut skip = m.skipped.clone();
    skip.push(store());
    for r in &m.roots {
        // 1. What was added, or changed kind, goes: deepest first.
        let now = walk(&r.path, &m.exclude, &skip).map_err(|e| format!("{}: {e}", r.path.display()))?;
        let mut gone: Vec<(&String, &PathBuf)> = now
            .iter()
            .filter(|(rel, (_, meta))| match r.entries.get(*rel) {
                None => true,
                Some(Entry::Dir { .. }) => !meta.is_dir(),
                Some(Entry::File { .. }) => !meta.is_file(),
                Some(Entry::Link { .. }) => !meta.file_type().is_symlink(),
            })
            .map(|(rel, (p, _))| (rel, p))
            .collect();
        gone.sort_by_key(|(rel, _)| std::cmp::Reverse(rel.matches('/').count()));
        for (rel, p) in gone {
            if let Err(e) = remove_entry(p) {
                failed.push(format!("{}: {e}", r.path.join(rel).display()));
            }
        }
        // 2. Then each entry of the snapshot, shallowest first, so every parent
        //    is a real directory before anything is written under it.
        let mut want: Vec<(&String, &Entry)> = r.entries.iter().collect();
        want.sort_by_key(|(rel, _)| rel.matches('/').count());
        for (rel, e) in want {
            let p = r.path.join(rel);
            if let Err(err) = restore_one(&r.path, &p, e) {
                failed.push(format!("{}: {err}", p.display()));
            }
        }
    }
    Ok((Some(before.id), d, failed))
}

/// Every component between `root` and `p` is a directory, not a link.
fn parents_are_dirs(root: &Path, p: &Path) -> bool {
    let mut cur = root.to_path_buf();
    let rel = p.strip_prefix(root).unwrap_or(p);
    let n = rel.components().count();
    for (i, c) in rel.components().enumerate() {
        if i + 1 == n {
            break;
        }
        cur.push(c);
        match fs::symlink_metadata(&cur) {
            Ok(m) if m.is_dir() => {}
            _ => return false,
        }
    }
    true
}

fn restore_one(root: &Path, p: &Path, e: &Entry) -> io::Result<()> {
    if !parents_are_dirs(root, p) {
        return Err(io::Error::other("a parent is not a directory (left as it is)"));
    }
    let cur = fs::symlink_metadata(p).ok();
    if let Some(m) = &cur {
        if same(e, p, m) {
            return Ok(());
        }
    }
    match e {
        Entry::Dir { mode } => {
            if cur.as_ref().is_none_or(|m| !m.is_dir()) {
                fs::create_dir(p)?;
            }
            set_mode(p, *mode);
        }
        Entry::Link { target } => {
            remove_entry(p)?;
            #[cfg(unix)]
            std::os::unix::fs::symlink(target, p)?;
            #[cfg(windows)]
            std::os::windows::fs::symlink_file(target, p)?;
        }
        Entry::File { mode, sha256, .. } => {
            let tmp = p.with_file_name(format!(".tartaros-restore-{}", std::process::id()));
            let _ = fs::remove_file(&tmp);
            fs::copy(object(sha256), &tmp)?;
            set_mode(&tmp, *mode);
            fs::rename(&tmp, p)?; // replaces a file or a link at `p`, never writes through it
        }
    }
    Ok(())
}
