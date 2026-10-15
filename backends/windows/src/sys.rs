//! Win32 side of the backend.

use std::ffi::{c_void, OsStr};
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

use tartaros_core::{Policy, RunError, RunOutcome};
use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, SetHandleInformation, FILETIME, HANDLE, HANDLE_FLAG_INHERIT, STILL_ACTIVE, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW, ConvertStringSidToSidW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, GetSecurityInfo,
    SetEntriesInAclW, SetNamedSecurityInfoW, SetSecurityInfo, EXPLICIT_ACCESS_W, GRANT_ACCESS,
    NO_MULTIPLE_TRUSTEE, SDDL_REVISION_1, SE_FILE_OBJECT, SE_WINDOW_OBJECT, TRUSTEE_IS_SID,
    TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
    GetAppContainerFolderPath,
};
use windows_sys::Win32::Security::{
    CreateRestrictedToken, SetTokenInformation, TokenDefaultDacl, TokenUser, TOKEN_DEFAULT_DACL, DISABLE_MAX_PRIVILEGE, SID_AND_ATTRIBUTES, TOKEN_ALL_ACCESS, TOKEN_USER, WRITE_RESTRICTED,
    FreeSid, GetSecurityDescriptorDacl, GetTokenInformation, TokenElevation, ACL,
    DACL_SECURITY_INFORMATION, NO_INHERITANCE, PROTECTED_DACL_SECURITY_INFORMATION, PSID,
    SECURITY_CAPABILITIES, TOKEN_ELEVATION, TOKEN_QUERY, UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::Security::Cryptography::{CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB};
use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_ANY};
use windows_sys::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_JOB_TIME,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::StationsAndDesktops::{
    CloseDesktop, CloseWindowStation, CreateDesktopW, CreateWindowStationW, GetProcessWindowStation,
    GetUserObjectInformationW, SetProcessWindowStation, UOI_NAME,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessAsUserW, CreateProcessW, CreateProcessWithLogonW, GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, GetCurrentProcess, LOGON_WITH_PROFILE, STARTUPINFOW, GetExitCodeProcess, InitializeProcThreadAttributeList,
    OpenProcessToken, ResumeThread, TerminateProcess, UpdateProcThreadAttribute, CREATE_NO_WINDOW,
    WaitForSingleObject, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
    EXTENDED_STARTUPINFO_PRESENT, INFINITE, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
    STARTF_USESTDHANDLES, STARTUPINFOEXW,
};

use crate::Grant;

const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x0002_0002;
const PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES: usize = 0x0002_0009;
const HR_ALREADY_EXISTS: i32 = 0x8007_00B7_u32 as i32;

const GENERIC_ALL: u32 = 0x1000_0000;
const READ_CONTROL: u32 = 0x2_0000;
const WINSTA_CREATE: u32 = 0x37F | READ_CONTROL | 0x4_0000;
const DESK_CREATE: u32 = 0x1FF | READ_CONTROL | 0x4_0000;

const DELETE: u32 = 0x1_0000;
const FILE_GENERIC_READ: u32 = 0x12_0089;
const FILE_GENERIC_WRITE: u32 = 0x12_0116;
const FILE_GENERIC_EXECUTE: u32 = 0x12_00A0;
// No FILE_DELETE_CHILD anywhere: a child is deleted through its own DELETE, so an
// object the grant does not reach cannot be deleted or replaced via its parent.
const MASK_WRITE: u32 = FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE;
const MASK_WRITE_NO_DELETE: u32 = FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE;
const MASK_READ: u32 = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;

/// Exit code reported when the policy timeout kills the run (same as Linux).
const EXIT_TIMEOUT: i32 = 124;

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(Some(0)).collect()
}

fn from_wide(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0;
    unsafe {
        while *p.add(n) != 0 {
            n += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
    }
}

/// Paths in a policy may use `/`; the security APIs get the native form.
fn native(p: &Path) -> Vec<u16> {
    wide(OsStr::new(&p.to_string_lossy().replace('/', "\\")))
}

fn err(reason: impl Into<String>) -> RunError {
    RunError { reason: reason.into() }
}

/// Quote one argument the way CommandLineToArgvW / the MSVC CRT parse it.
fn quote(arg: &str, out: &mut String) {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
        out.push_str(arg);
        return;
    }
    out.push('"');
    let mut backslashes = 0;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.extend(std::iter::repeat('\\').take(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.extend(std::iter::repeat('\\').take(backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    out.extend(std::iter::repeat('\\').take(backslashes * 2));
    out.push('"');
}

// ---------------------------------------------------------------- DACLs (SDDL)

/// The DACL a path had before we touched it, kept until restore.
struct Saved {
    path: Vec<u16>,
    sddl: String,
}

/// Split "D:PAI(A;..)(A;..)" into its flags ("PAI") and ACE strings.
fn split_dacl(sddl: &str) -> Result<(String, Vec<String>), String> {
    let body = sddl.strip_prefix("D:").ok_or(format!("unexpected SDDL {sddl}"))?;
    let open = body.find('(').unwrap_or(body.len());
    let flags = body[..open].to_string();
    let mut aces = Vec::new();
    let (mut depth, mut cur) = (0, String::new());
    for c in body[open..].chars() {
        match c {
            '(' if depth == 0 => depth = 1,
            ')' if depth == 1 => {
                aces.push(std::mem::take(&mut cur));
                depth = 0;
            }
            // Conditional ACEs carry nested parentheses; refuse rather than mangle.
            '(' | ')' => return Err("conditional ACE in DACL: not supported".into()),
            _ => cur.push(c),
        }
    }
    Ok((flags, aces))
}

fn ace_field(ace: &str, i: usize) -> &str {
    ace.split(';').nth(i).unwrap_or("")
}

/// The same ACE with the INHERITED flag dropped (it becomes explicit).
fn explicit(ace: &str) -> String {
    let mut f: Vec<String> = ace.split(';').map(String::from).collect();
    if f.len() > 1 {
        let flags = f[1].clone();
        f[1] = flags
            .as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap_or(""))
            .filter(|t| *t != "ID")
            .collect();
    }
    f.join(";")
}

unsafe fn read_sddl(wp: &[u16]) -> Result<String, String> {
    let mut sd: *mut c_void = null_mut();
    let rc = GetNamedSecurityInfoW(
        wp.as_ptr(),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        null_mut(),
        null_mut(),
        null_mut(),
        null_mut(),
        &mut sd,
    );
    if rc != 0 {
        return Err(format!("GetNamedSecurityInfo: error {rc}"));
    }
    let mut out: *mut u16 = null_mut();
    let ok = ConvertSecurityDescriptorToStringSecurityDescriptorW(
        sd,
        SDDL_REVISION_1,
        DACL_SECURITY_INFORMATION,
        &mut out,
        null_mut(),
    );
    LocalFree(sd);
    if ok == 0 {
        return Err(format!("ConvertSecurityDescriptorToString: {}", std::io::Error::last_os_error()));
    }
    let s = from_wide(out);
    LocalFree(out as *mut c_void);
    Ok(s)
}

unsafe fn write_sddl(wp: &[u16], sddl: &str) -> Result<(), String> {
    let ws = wide(OsStr::new(sddl));
    let mut sd: *mut c_void = null_mut();
    if ConvertStringSecurityDescriptorToSecurityDescriptorW(ws.as_ptr(), SDDL_REVISION_1, &mut sd, null_mut()) == 0 {
        return Err(format!("bad SDDL {sddl}: {}", std::io::Error::last_os_error()));
    }
    let (mut present, mut defaulted) = (0, 0);
    let mut dacl: *mut ACL = null_mut();
    GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted);
    let protect = split_dacl(sddl)?.0.contains('P');
    let info = DACL_SECURITY_INFORMATION
        | if protect { PROTECTED_DACL_SECURITY_INFORMATION } else { UNPROTECTED_DACL_SECURITY_INFORMATION };
    let rc = SetNamedSecurityInfoW(wp.as_ptr() as *mut u16, SE_FILE_OBJECT, info, null_mut(), null_mut(), dacl, null());
    LocalFree(sd);
    if rc != 0 {
        return Err(format!("SetNamedSecurityInfo: error {rc}"));
    }
    Ok(())
}

/// Rewrite one path's DACL for `grant`, returning what it had before.
unsafe fn apply(path: &Path, sid: &str, grant: Grant) -> Result<Saved, String> {
    let wp = native(path);
    let before = read_sddl(&wp).map_err(|e| format!("{}: {e}", path.display()))?;
    let (flags, aces) = split_dacl(&before)?;
    let to_sddl = |prefix: &str, v: &[String]| format!("D:{prefix}{}", v.iter().map(|a| format!("({a})")).collect::<String>());
    let new = match grant {
        // Unprotected: pass only the explicit ACEs; inheritance is recomputed.
        Grant::Write | Grant::Read | Grant::ExecFile => {
            let mut v: Vec<String> = aces.iter().filter(|a| !ace_field(a, 1).contains("ID")).cloned().collect();
            match grant {
                Grant::Write => {
                    v.push(format!("A;;0x{MASK_WRITE_NO_DELETE:x};;;{sid}"));
                    v.push(format!("A;OICIIO;0x{MASK_WRITE:x};;;{sid}"));
                }
                Grant::Read => v.push(format!("A;OICI;0x{MASK_READ:x};;;{sid}")),
                _ => v.push(format!("A;;0x{MASK_READ:x};;;{sid}")),
            }
            to_sddl(&flags.replace('P', ""), &v)
        }
        // Protected: freeze every ACE the object has now as explicit, minus
        // anything granted to the container, plus the container's narrower grant.
        Grant::Pin | Grant::ProtectReadOnly | Grant::ProtectNoAccess => {
            let mut v: Vec<String> = aces
                .iter()
                .filter(|a| !ace_field(a, 5).eq_ignore_ascii_case(sid))
                .map(|a| explicit(a))
                .collect();
            match grant {
                Grant::Pin => {
                    v.push(format!("A;;0x{MASK_WRITE_NO_DELETE:x};;;{sid}"));
                    v.push(format!("A;OICIIO;0x{MASK_WRITE:x};;;{sid}"));
                }
                Grant::ProtectReadOnly => v.push(format!("A;OICI;0x{MASK_READ:x};;;{sid}")),
                _ => {}
            }
            // Deny ACEs first, as canonical order requires.
            v.sort_by_key(|a| !a.starts_with("D;"));
            to_sddl("P", &v)
        }
    };
    write_sddl(&wp, &new).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(Saved { path: wp, sddl: before })
}

/// Undo in reverse order: a child goes back before its parent's grant is
/// withdrawn, so inherited ACEs are recomputed last. Returns what failed.
unsafe fn restore(saved: Vec<Saved>) -> Vec<String> {
    let mut failed = Vec::new();
    for s in saved.into_iter().rev() {
        if let Err(e) = write_sddl(&s.path, &s.sddl) {
            failed.push(format!("{} ({e})", from_wide(s.path.as_ptr())));
        }
    }
    failed
}

/// Sandbox-user tier: add the user's ACEs (see `crate::user_aces`) to the path's
/// explicit ones, keeping its protection flag. Deny ACEs bind a user SID, so the
/// DACL is never frozen; restore puts the original SDDL back.
unsafe fn apply_user(path: &Path, sid: &str, grant: Grant) -> Result<Saved, String> {
    let wp = native(path);
    let before = read_sddl(&wp).map_err(|e| format!("{}: {e}", path.display()))?;
    let (flags, aces) = split_dacl(&before)?;
    let mut v: Vec<String> = aces.iter().filter(|a| !ace_field(a, 1).contains("ID")).cloned().collect();
    v.extend(crate::user_aces(grant, sid));
    // Deny ACEs first, as canonical order requires.
    v.sort_by_key(|a| !a.starts_with("D;"));
    let new = format!("D:{flags}{}", v.iter().map(|a| format!("({a})")).collect::<String>());
    write_sddl(&wp, &new).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(Saved { path: wp, sddl: before })
}

// ------------------------------------------------------------------ journal

/// Write-ahead record of every DACL a run changes, so a run that dies (killed,
/// crashed, power loss) does not leave its grants behind: the next run puts the
/// recorded DACLs back. One file per run in %LOCALAPPDATA%\tartaros\journal:
///
/// ```text
/// run <pid> <process creation time>
/// container <AppContainer profile name>      (AppContainer tier only)
/// acl <path>\t<SDDL before the change>        (one per path, before it changes)
/// made <path>                                 (a placeholder dir this run created)
/// ```
///
/// Tab and newline cannot appear in a Windows path, so the format needs no
/// escaping. Recovery restores a dead run's entries in reverse order, except a
/// path that a live run's journal also names: rolling that back would also undo
/// the live run's change (possibly a deny), so it waits until that run is gone.
struct Journal {
    path: PathBuf,
    file: std::fs::File,
}

fn journal_dir() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(|d| PathBuf::from(d).join("tartaros").join("journal"))
}

unsafe fn creation_time(process: HANDLE) -> Option<u64> {
    let (mut c, mut e, mut k, mut u): (FILETIME, FILETIME, FILETIME, FILETIME) = (zeroed(), zeroed(), zeroed(), zeroed());
    if GetProcessTimes(process, &mut c, &mut e, &mut k, &mut u) == 0 {
        return None;
    }
    Some(((c.dwHighDateTime as u64) << 32) | c.dwLowDateTime as u64)
}

/// Whether the run that wrote a journal is still alive (same pid AND same start
/// time, so a recycled pid does not count).
unsafe fn run_alive(pid: u32, created: u64) -> bool {
    let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
    if h.is_null() {
        return false;
    }
    let mut code = 0u32;
    let alive = GetExitCodeProcess(h, &mut code) != 0 && code == STILL_ACTIVE as u32 && creation_time(h) == Some(created);
    CloseHandle(h);
    alive
}

impl Journal {
    unsafe fn open(tag: &str, container: Option<&str>) -> Result<Journal, String> {
        use std::io::Write;
        let dir = journal_dir().ok_or("LOCALAPPDATA is not set: no place for the ACL journal")?;
        std::fs::create_dir_all(&dir).map_err(|e| format!("journal dir {}: {e}", dir.display()))?;
        let path = dir.join(format!("{tag}.journal"));
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)
            .map_err(|e| format!("journal {}: {e}", path.display()))?;
        let created = creation_time(GetCurrentProcess()).unwrap_or(0);
        let mut head = format!("run {} {created}\n", std::process::id());
        if let Some(c) = container {
            head.push_str(&format!("container {c}\n"));
        }
        file.write_all(head.as_bytes()).and_then(|_| file.sync_data()).map_err(|e| format!("journal write: {e}"))?;
        Ok(Journal { path, file })
    }

    /// Record `path`'s current DACL; durable before the caller changes it.
    fn record(&mut self, path: &Path, sddl: &str) -> Result<(), String> {
        use std::io::Write;
        self.file
            .write_all(format!("acl {}\t{sddl}\n", path.display()).as_bytes())
            .and_then(|_| self.file.sync_data())
            .map_err(|e| format!("journal write: {e}"))
    }

    /// Record a placeholder directory this run just created.
    fn record_made(&mut self, path: &Path) -> Result<(), String> {
        use std::io::Write;
        self.file
            .write_all(format!("made {}\n", path.display()).as_bytes())
            .and_then(|_| self.file.sync_data())
            .map_err(|e| format!("journal write: {e}"))
    }

    /// The run restored everything: the journal is no longer needed.
    fn finish(self) {
        drop(self.file);
        std::fs::remove_file(&self.path).ok();
    }
}

/// Create the run's placeholder directories (see `crate::placeholder_plan`).
/// `create_dir` (not `_all`): the plan lists parents first, and one that
/// appeared meanwhile is not ours and is left alone. Each is journaled right
/// after it is created, so recovery only ever removes directories this backend
/// made (a crash between the two leaves at most one empty directory).
fn make_placeholders(policy: &Policy, journal: &mut Journal) -> Result<Vec<PathBuf>, String> {
    let mut made = Vec::new();
    for d in crate::placeholder_plan(policy) {
        match std::fs::create_dir(&d) {
            Ok(()) => {
                made.push(d.clone());
                if let Err(e) = journal.record_made(&d) {
                    remove_placeholders(&made);
                    return Err(e);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => {
                remove_placeholders(&made);
                return Err(format!("placeholder {}: {e}", d.display()));
            }
        }
    }
    Ok(made)
}

/// Remove placeholder directories, deepest first. `remove_dir` only removes an
/// empty directory, so nothing the run wrote can be lost; returns the ones kept.
fn remove_placeholders(made: &[PathBuf]) -> Vec<String> {
    let mut kept = Vec::new();
    for d in made.iter().rev() {
        if d.exists() && std::fs::remove_dir(d).is_err() {
            kept.push(d.display().to_string());
        }
    }
    kept
}

/// Put back what dead runs left behind. Called at the start of every run.
/// Returns a note for stderr when something was recovered or could not be.
/// One journal file, parsed.
struct JournalFile {
    path: PathBuf,
    pid: u32,
    alive: bool,
    container: Option<String>,
    entries: Vec<(String, String)>,
    made: Vec<PathBuf>,
}

fn parse_journal(path: PathBuf) -> Option<JournalFile> {
    let text = std::fs::read_to_string(&path).ok()?;
    let mut lines = text.lines();
    let mut head = lines.next()?.split(' ');
    let (pid, created) = match (head.next(), head.next(), head.next()) {
        (Some("run"), Some(p), Some(c)) => (p.parse::<u32>().ok()?, c.parse::<u64>().ok()?),
        _ => return None,
    };
    let mut container = None;
    let mut entries = Vec::new();
    let mut made = Vec::new();
    for l in lines {
        if let Some(m) = l.strip_prefix("made ") {
            made.push(PathBuf::from(m));
        } else if let Some(c) = l.strip_prefix("container ") {
            container = Some(c.to_string());
        } else if let Some((p, sddl)) = l.strip_prefix("acl ").and_then(|r| r.split_once('\t')) {
            entries.push((p.to_string(), sddl.to_string()));
        }
    }
    let alive = unsafe { run_alive(pid, created) };
    Some(JournalFile { path, pid, alive, container, entries, made })
}

unsafe fn recover_orphans() -> Option<String> {
    let dir = journal_dir()?;
    let journals: Vec<JournalFile> = std::fs::read_dir(&dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().map_or(false, |e| e == "journal"))
        .filter_map(parse_journal)
        .collect();
    let live: Vec<&str> = journals.iter().filter(|j| j.alive).flat_map(|j| j.entries.iter().map(|(p, _)| p.as_str())).collect();
    let mut notes = Vec::new();
    for j in journals.iter().filter(|j| !j.alive) {
        let (path, pid, container, entries) = (&j.path, j.pid, &j.container, &j.entries);
        let made_by_live = j.made.iter().any(|m| live.iter().any(|l| Path::new(l).starts_with(m)));
        if made_by_live || entries.iter().any(|(p, _)| live.iter().any(|l| l.eq_ignore_ascii_case(p))) {
            notes.push(format!("dead run {pid} shares paths with a live run; its ACLs are restored once that run ends"));
            continue;
        }
        let mut failed = Vec::new();
        for (p, sddl) in entries.iter().rev() {
            if let Err(e) = write_sddl(&native(Path::new(p)), sddl) {
                // A path that is gone has no grant left to undo.
                if Path::new(p).exists() {
                    failed.push(format!("{p} ({e})"));
                }
            }
        }
        if let Some(c) = &container {
            DeleteAppContainerProfile(wide(OsStr::new(c)).as_ptr());
        }
        // Only after the ACLs are back (a placeholder's own DACL is among them).
        let kept = remove_placeholders(&j.made);
        if !kept.is_empty() {
            notes.push(format!("left non-empty placeholders of dead run {pid}: {}", kept.join(", ")));
        }
        if failed.is_empty() {
            std::fs::remove_file(path).ok();
            notes.push(format!("restored {} ACL(s) left by dead run {pid}", entries.len()));
        } else {
            notes.push(format!("could not restore ACLs left by dead run {pid}: {}", failed.join(", ")));
        }
    }
    (!notes.is_empty()).then(|| notes.join("; "))
}

// ------------------------------------------------------------ desktop / winsta

unsafe fn grant_handle(h: HANDLE, sid: PSID, mask: u32) -> Result<(*mut c_void, *mut ACL), String> {
    let mut dacl: *mut ACL = null_mut();
    let mut sd: *mut c_void = null_mut();
    let rc = GetSecurityInfo(h, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION, null_mut(), null_mut(), &mut dacl, null_mut(), &mut sd);
    if rc != 0 {
        return Err(format!("GetSecurityInfo: error {rc}"));
    }
    let ea = EXPLICIT_ACCESS_W {
        grfAccessPermissions: mask,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: NO_INHERITANCE,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: sid as *mut u16,
        },
    };
    let mut new_dacl: *mut ACL = null_mut();
    let rc = SetEntriesInAclW(1, &ea, dacl, &mut new_dacl);
    if rc != 0 {
        LocalFree(sd);
        return Err(format!("SetEntriesInAcl (window object): error {rc}"));
    }
    let rc = SetSecurityInfo(h, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION, null_mut(), null_mut(), new_dacl, null());
    LocalFree(new_dacl as *mut c_void);
    if rc != 0 {
        LocalFree(sd);
        return Err(format!("SetSecurityInfo (window object): error {rc}"));
    }
    Ok((sd, dacl))
}

/// The desktop the process runs on, and what to undo when it exits.
struct Desk {
    winsta: HANDLE,
    /// true: a window station created for this run. false: the caller's, whose
    /// DACL got a read-only container ACE that `close` takes back.
    own_winsta: bool,
    winsta_saved: Option<(*mut c_void, *mut ACL)>,
    desk: HANDLE,
    lp: Vec<u16>,
}

impl Desk {
    unsafe fn close(self) {
        CloseDesktop(self.desk);
        if let Some(saved) = self.winsta_saved {
            SetSecurityInfo(self.winsta, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION, null_mut(), null_mut(), saved.1, null());
            LocalFree(saved.0);
        }
        if self.own_winsta {
            CloseWindowStation(self.winsta);
        }
    }
}

/// A desktop that exists only for this run: anything that loads user32 needs
/// one it may use. First choice is a private window station too (separate
/// clipboard and atoms); a non-interactive logon (sshd, a service) may not create
/// one, and then the desktop goes on the caller's window station.
unsafe fn private_desktop(sid: PSID, tag: &str, shared_winsta_mask: u32) -> Result<Desk, String> {
    let original = GetProcessWindowStation();
    let created = CreateWindowStationW(null(), 0, WINSTA_CREATE, null());
    let (winsta, own_winsta) = if created.is_null() { (original, false) } else { (created, true) };
    if own_winsta && SetProcessWindowStation(winsta) == 0 {
        CloseWindowStation(winsta);
        return Err(format!("SetProcessWindowStation: {}", std::io::Error::last_os_error()));
    }
    let desk_name = wide(OsStr::new(&format!("tartaros-{tag}")));
    let desk = CreateDesktopW(desk_name.as_ptr(), null(), null(), 0, DESK_CREATE, null());
    let desk_err = std::io::Error::last_os_error();
    if own_winsta {
        SetProcessWindowStation(original);
    }
    if desk.is_null() {
        if own_winsta {
            CloseWindowStation(winsta);
        }
        return Err(format!("CreateDesktop: {desk_err}"));
    }
    // Own window station: full access. Shared one: what the caller passes.
    let winsta_mask = if own_winsta { GENERIC_ALL } else { shared_winsta_mask };
    let mut d = Desk { winsta, own_winsta, winsta_saved: None, desk, lp: Vec::new() };
    match grant_handle(winsta, sid, winsta_mask) {
        Ok(saved) if own_winsta => {
            LocalFree(saved.0);
        }
        Ok(saved) => d.winsta_saved = Some(saved),
        Err(e) => {
            d.close();
            return Err(e);
        }
    }
    match grant_handle(desk, sid, GENERIC_ALL) {
        Ok(saved) => {
            LocalFree(saved.0);
        }
        Err(e) => {
            d.close();
            return Err(e);
        }
    }
    let mut buf = [0u16; 256];
    let mut needed = 0u32;
    GetUserObjectInformationW(winsta, UOI_NAME, buf.as_mut_ptr() as *mut c_void, (buf.len() * 2) as u32, &mut needed);
    d.lp = wide(OsStr::new(&format!("{}\\{}", from_wide(buf.as_ptr()), from_wide(desk_name.as_ptr()))));
    Ok(d)
}

// ------------------------------------------------------------------- the run

/// Container profile + SID for one run, deleted when dropped.
struct Container {
    name: Vec<u16>,
    sid: PSID,
    sid_str: String,
}

impl Container {
    unsafe fn create(tag: &str) -> Result<Self, String> {
        let name = wide(OsStr::new(&format!("tartaros.{tag}")));
        let mut sid: PSID = null_mut();
        let hr = CreateAppContainerProfile(name.as_ptr(), name.as_ptr(), name.as_ptr(), null(), 0, &mut sid);
        if hr == HR_ALREADY_EXISTS {
            let hr = DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &mut sid);
            if hr != 0 {
                return Err(format!("DeriveAppContainerSidFromAppContainerName: 0x{hr:08x}"));
            }
        } else if hr != 0 {
            return Err(format!("CreateAppContainerProfile: 0x{hr:08x}"));
        }
        let mut s: *mut u16 = null_mut();
        ConvertSidToStringSidW(sid, &mut s);
        let sid_str = from_wide(s);
        LocalFree(s as *mut c_void);
        Ok(Container { name, sid, sid_str })
    }

    /// The container's own folder (%LOCALAPPDATA%\Packages\<name>\AC), which it
    /// may write: the place for TEMP/TMP, so tools don't litter the workspace.
    unsafe fn folder(&self) -> Option<PathBuf> {
        let ws = wide(OsStr::new(&self.sid_str));
        let mut p: *mut u16 = null_mut();
        if GetAppContainerFolderPath(ws.as_ptr(), &mut p) != 0 {
            return None;
        }
        let s = from_wide(p);
        windows_sys::Win32::System::Com::CoTaskMemFree(p as *const c_void);
        Some(PathBuf::from(s))
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        unsafe {
            FreeSid(self.sid);
            DeleteAppContainerProfile(self.name.as_ptr());
        }
    }
}

/// `temp`: TEMP/TMP for the child. `profile`: the sandbox user's profile, which
/// replaces the caller's USERPROFILE/APPDATA/LOCALAPPDATA (and TEMP/TMP).
/// `extra`: one more variable, set even under `inherit_env`.
fn env_block(policy: &Policy, temp: Option<&Path>, profile: Option<&Path>, extra: Option<(&str, &str)>) -> Option<Vec<u16>> {
    let mut vars: Vec<(String, String)> = match policy.child_env() {
        // inherit_env: the caller opted into full passthrough.
        None if extra.is_none() => return None,
        None => std::env::vars().collect(),
        Some(v) => v,
    };
    if let Some((k, v)) = extra {
        vars.retain(|(n, _)| !n.eq_ignore_ascii_case(k));
        vars.push((k.to_string(), v.to_string()));
    }
    let has = |vars: &[(String, String)], k: &str| vars.iter().any(|(n, _)| n.eq_ignore_ascii_case(k));
    // The Unix allowlist matches names case-sensitively; Windows names are
    // case-insensitive (`Path`, `TEMP`), so bring those over too.
    for (k, v) in std::env::vars() {
        let wanted = tartaros_core::ENV_ALLOWLIST.iter().any(|a| a.eq_ignore_ascii_case(&k))
            || crate::WINDOWS_ENV_BASELINE.iter().any(|a| a.eq_ignore_ascii_case(&k));
        if wanted && !has(&vars, &k) {
            vars.push((k, v));
        }
    }
    let profile_temp = profile.map(|p| p.join("AppData").join("Local").join("Temp"));
    if let Some(p) = profile {
        let set = [
            ("USERPROFILE", p.to_path_buf()),
            ("APPDATA", p.join("AppData").join("Roaming")),
            ("LOCALAPPDATA", p.join("AppData").join("Local")),
        ];
        vars.retain(|(k, _)| !set.iter().any(|(n, _)| n.eq_ignore_ascii_case(k)));
        for (n, v) in set {
            vars.push((n.into(), v.to_string_lossy().into_owned()));
        }
    }
    if let Some(t) = temp.or(profile_temp.as_deref()) {
        vars.retain(|(k, _)| !k.eq_ignore_ascii_case("TEMP") && !k.eq_ignore_ascii_case("TMP"));
        let t = t.to_string_lossy().into_owned();
        vars.push(("TEMP".into(), t.clone()));
        vars.push(("TMP".into(), t));
    }
    vars.sort_by_key(|(k, _)| k.to_uppercase());
    if std::env::var_os("TARTAROS_DEBUG").is_some() {
        for (k, v) in &vars {
            eprintln!("[env] {k}={}", v.chars().take(60).collect::<String>());
        }
    }
    let mut block: Vec<u16> = Vec::new();
    for (k, v) in vars {
        block.extend(OsStr::new(&format!("{k}={v}")).encode_wide());
        block.push(0);
    }
    block.push(0);
    Some(block)
}

pub(crate) fn run(policy: &Policy, command: &[String]) -> Result<RunOutcome, RunError> {
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let tag = format!(
        "{}.{}",
        std::process::id(),
        COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    unsafe {
        if let Some(note) = recover_orphans() {
            eprintln!("tartaros: {note}");
        }
        let container = Container::create(&tag).map_err(err)?;
        prepare(policy)?;
        let program = Path::new(&command[0]);
        let program = program.is_absolute().then_some(program);

        let mut journal = Journal::open(&tag, Some(&format!("tartaros.{tag}"))).map_err(err)?;
        // On any failure before the agent runs, the placeholders and ACLs have
        // already been undone (make_placeholders / apply_plan clean up their own),
        // so the journal describes nothing left on disk: drop it with finish().
        let made = match make_placeholders(policy, &mut journal) {
            Ok(m) => m,
            Err(e) => {
                journal.finish();
                return Err(err(e));
            }
        };
        let saved = match apply_plan(policy, program, &mut journal, |path, grant| apply(path, &container.sid_str, grant)) {
            Ok(s) => s,
            Err(e) => {
                remove_placeholders(&made);
                journal.finish();
                return Err(e);
            }
        };

        let outcome = spawn(policy, command, &container, &tag);
        let failed = restore(saved);
        drop(container);
        if !failed.is_empty() {
            // The journal stays: the next run retries the restore.
            return Err(err(format!("run finished but ACL restore failed:{}", restore_note(&failed))));
        }
        warn_kept(&remove_placeholders(&made));
        journal.finish();
        outcome
    }
}

/// Checks and preparation shared by both tiers, before any ACL is touched.
fn prepare(policy: &Policy) -> Result<(), RunError> {
    let absent = crate::absent_write_denies(policy);
    if !absent.is_empty() {
        let list: Vec<String> = absent.iter().map(|p| p.display().to_string()).collect();
        return Err(err(format!(
            "unsupported on Windows: write-deny on a path that does not exist yet ({}); \
             an ACL cannot name a missing file, so the run is refused instead of left able to create it",
            list.join(", ")
        )));
    }
    if policy.materialize_absent_handoff {
        materialize(policy).map_err(err)?;
    }
    Ok(())
}

/// Apply the policy's ACL plan with `apply_one`; on the first failure, undo what
/// was applied and fail.
unsafe fn apply_plan(
    policy: &Policy,
    program: Option<&Path>,
    journal: &mut Journal,
    apply_one: impl Fn(&Path, Grant) -> Result<Saved, String>,
) -> Result<Vec<Saved>, RunError> {
    let mut saved = Vec::new();
    let debug = std::env::var_os("TARTAROS_DEBUG").is_some();
    for (path, grant) in crate::acl_plan(policy, program) {
        if debug {
            eprintln!("[acl] {grant:?} {}", path.display());
        }
        // Journal first: if this process dies right after the change, the next
        // run can still put the DACL back.
        let recorded = read_sddl(&native(&path))
            .map_err(|e| format!("{}: {e}", path.display()))
            .and_then(|before| journal.record(&path, &before));
        let result = recorded.and_then(|_| apply_one(&path, grant));
        match result {
            Ok(s) => {
                if debug {
                    eprintln!("      -> {}", read_sddl(&native(&path)).unwrap_or_default());
                }
                saved.push(s)
            }
            Err(e) => {
                let failed = restore(saved);
                return Err(err(format!("applying ACLs: {e}{}", restore_note(&failed))));
            }
        }
    }
    Ok(saved)
}

/// Create the absent top-level trust-handoff paths so they exist to be protected
/// (an ACE cannot name a missing object). Same rules as the Linux backend: never
/// through a symlink or junction, never clobbering an existing file.
fn materialize(policy: &Policy) -> Result<(), String> {
    for p in policy.handoff_placeholders() {
        let root = policy.writable_roots.iter().find(|r| p.starts_with(r));
        let mut a = p.parent();
        while let (Some(dir), Some(root)) = (a, root) {
            if !dir.starts_with(root) {
                break;
            }
            if std::fs::symlink_metadata(dir).map(|m| m.file_type().is_symlink()).unwrap_or(false) {
                return Err(format!("materialize: refusing to act through a link: {}", dir.display()));
            }
            a = dir.parent();
        }
        let parent = p.parent().ok_or_else(|| format!("materialize: no parent for {}", p.display()))?;
        std::fs::create_dir_all(parent).map_err(|e| format!("materialize mkdir {}: {e}", parent.display()))?;
        let is_dir = p.file_name().map(|n| n == "workflows").unwrap_or(false);
        if is_dir {
            std::fs::create_dir_all(&p).map_err(|e| format!("materialize mkdir {}: {e}", p.display()))?;
        } else {
            match std::fs::OpenOptions::new().write(true).create_new(true).open(&p) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(format!("materialize create {}: {e}", p.display())),
            }
        }
        if !p.exists() {
            return Err(format!("materialize: {} missing after create", p.display()));
        }
    }
    Ok(())
}

/// A placeholder that is not empty after the run was written into by someone
/// with more rights than the agent; it is left for the user to look at.
fn warn_kept(kept: &[String]) {
    if !kept.is_empty() {
        eprintln!("tartaros: placeholder directories not empty after the run, left in place: {}", kept.join(", "));
    }
}

fn restore_note(failed: &[String]) -> String {
    if failed.is_empty() {
        String::new()
    } else {
        format!(" (restore FAILED for: {})", failed.join(", "))
    }
}

unsafe fn spawn(policy: &Policy, command: &[String], c: &Container, tag: &str) -> Result<RunOutcome, RunError> {
    // Job first; the process starts suspended and is assigned before it runs,
    // so nothing executes outside the caps.
    let job = make_job(policy)?;

    // Shared window station: enumerate, read attributes, global atoms (what
    // user32 init needs), nothing else.
    let mut desk = match private_desktop(c.sid, tag, 0x1 | 0x2 | 0x20 | READ_CONTROL) {
        Ok(d) => d,
        Err(e) => {
            CloseHandle(job);
            return Err(err(format!("private desktop: {e}")));
        }
    };

    let mut caps = SECURITY_CAPABILITIES { AppContainerSid: c.sid, Capabilities: null_mut(), CapabilityCount: 0, Reserved: 0 };
    let mut std_handles: Vec<HANDLE> = Vec::new();
    for which in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        let h = GetStdHandle(which);
        if !h.is_null() && h as isize != -1 && !std_handles.contains(&h) {
            SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
            std_handles.push(h);
        }
    }
    let mut size = 0usize;
    InitializeProcThreadAttributeList(null_mut(), 2, 0, &mut size);
    let mut buf = vec![0u8; size];
    let list = buf.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
    let ok = InitializeProcThreadAttributeList(list, 2, 0, &mut size) != 0
        && UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &mut caps as *mut _ as *const c_void, size_of::<SECURITY_CAPABILITIES>(), null_mut(), null()) != 0
        && (std_handles.is_empty()
            || UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, std_handles.as_ptr() as *const c_void, std_handles.len() * size_of::<HANDLE>(), null_mut(), null()) != 0);
    if !ok {
        let e = std::io::Error::last_os_error();
        desk.close();
        CloseHandle(job);
        return Err(err(format!("process attributes: {e}")));
    }

    let mut si: STARTUPINFOEXW = zeroed();
    si.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.StartupInfo.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.StartupInfo.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    si.StartupInfo.lpDesktop = desk.lp.as_mut_ptr();
    si.lpAttributeList = list;

    let cmdline = command_line(command);
    if std::env::var_os("TARTAROS_DEBUG").is_some() {
        eprintln!("[cmdline] {cmdline}");
    }
    let mut cmdline_w = wide(OsStr::new(&cmdline));
    let temp = c.folder().map(|f| f.join("Temp")).filter(|t| t.is_dir());
    let env = env_block(policy, temp.as_deref(), None, None);
    let cwd = working_dir(policy);

    let mut pi: PROCESS_INFORMATION = zeroed();
    let created = CreateProcessW(
        null(),
        cmdline_w.as_mut_ptr(),
        null(),
        null(),
        (!std_handles.is_empty()) as i32,
        CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
        env.as_ref().map_or(null(), |e| e.as_ptr() as *const c_void),
        cwd.as_ref().map_or(null(), |c| c.as_ptr()),
        &si.StartupInfo,
        &mut pi,
    );
    if created == 0 {
        let e = std::io::Error::last_os_error();
        desk.close();
        CloseHandle(job);
        return Err(err(format!("CreateProcess {}: {e}", command[0])));
    }
    if AssignProcessToJobObject(job, pi.hProcess) == 0 {
        let e = std::io::Error::last_os_error();
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        desk.close();
        CloseHandle(job);
        return Err(err(format!("AssignProcessToJobObject: {e}")));
    }
    ResumeThread(pi.hThread);
    let exit_code = wait_exit(policy, job, pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    // Teardown: closing the job kills every descendant still alive (no daemon
    // outlives the run), then the private desktop goes.
    CloseHandle(job);
    desk.close();
    Ok(RunOutcome { exit_code })
}

// ------------------------------------------------------- sandbox-user tier

const SBX_KEY: &str = r"SOFTWARE\tartaros\SandboxUser";

/// One value from HKLM\SOFTWARE\tartaros\SandboxUser (or another HKLM key).
unsafe fn reg_value(key: &str, name: &str) -> Result<Vec<u8>, String> {
    let (k, n) = (wide(OsStr::new(key)), wide(OsStr::new(name)));
    let mut len = 0u32;
    let rc = RegGetValueW(HKEY_LOCAL_MACHINE, k.as_ptr(), n.as_ptr(), RRF_RT_ANY, null_mut(), null_mut(), &mut len);
    if rc != 0 {
        return Err(format!("HKLM\\{key}\\{name}: error {rc}"));
    }
    let mut buf = vec![0u8; len as usize];
    let rc = RegGetValueW(HKEY_LOCAL_MACHINE, k.as_ptr(), n.as_ptr(), RRF_RT_ANY, null_mut(), buf.as_mut_ptr() as *mut c_void, &mut len);
    if rc != 0 {
        return Err(format!("HKLM\\{key}\\{name}: error {rc}"));
    }
    buf.truncate(len as usize);
    Ok(buf)
}

/// A REG_SZ / REG_EXPAND_SZ value (RegGetValue expands the latter).
unsafe fn reg_string(key: &str, name: &str) -> Result<String, String> {
    let b = reg_value(key, name)?;
    let w: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&c| c != 0).collect();
    Ok(String::from_utf16_lossy(&w))
}

/// The sandbox identity installed by `setup/sandbox-user.ps1`.
struct SandboxUser {
    name: Vec<u16>,
    sid_str: String,
    sid: PSID,
    /// UTF-16, NUL-terminated; wiped on drop.
    password: Vec<u16>,
    profile: Option<PathBuf>,
}

impl SandboxUser {
    unsafe fn load() -> Result<Self, String> {
        let missing = |e: String| format!("sandbox user not installed (run setup/sandbox-user.ps1 install, elevated, once): {e}");
        let name = reg_string(SBX_KEY, "User").map_err(missing)?;
        let sid_str = reg_string(SBX_KEY, "Sid").map_err(missing)?;
        let mut blob = reg_value(SBX_KEY, "Blob").map_err(missing)?;
        let input = CRYPT_INTEGER_BLOB { cbData: blob.len() as u32, pbData: blob.as_mut_ptr() };
        let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: null_mut() };
        if CryptUnprotectData(&input, null_mut(), null(), null(), null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out) == 0 {
            return Err(format!("CryptUnprotectData: {}", std::io::Error::last_os_error()));
        }
        let bytes = std::slice::from_raw_parts_mut(out.pbData, out.cbData as usize);
        // Exact capacity, so the Vec never reallocates and leaves a copy of the
        // password in freed memory.
        let mut password: Vec<u16> = Vec::with_capacity(bytes.len() / 2 + 1);
        password.extend(bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])));
        password.push(0);
        for b in bytes.iter_mut() {
            std::ptr::write_volatile(b, 0);
        }
        LocalFree(out.pbData as *mut c_void);
        let zero = |p: &mut Vec<u16>| {
            for c in p.iter_mut() {
                std::ptr::write_volatile(c, 0);
            }
        };
        let mut sid: PSID = null_mut();
        let ws = wide(OsStr::new(&sid_str));
        if ConvertStringSidToSidW(ws.as_ptr(), &mut sid) == 0 {
            zero(&mut password);
            return Err(format!("bad sandbox SID {sid_str}: {}", std::io::Error::last_os_error()));
        }
        let profile_key = format!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid_str}");
        let profile = reg_string(&profile_key, "ProfileImagePath").ok().map(PathBuf::from).filter(|p| p.is_absolute());
        Ok(SandboxUser { name: wide(OsStr::new(&name)), sid_str, sid, password, profile })
    }
}

impl Drop for SandboxUser {
    fn drop(&mut self) {
        for c in self.password.iter_mut() {
            unsafe { std::ptr::write_volatile(c, 0) };
        }
        unsafe { LocalFree(self.sid) };
    }
}

/// Fail closed if the sandbox user's per-SID WFP egress-block filter is not
/// present. On this tier "network denied" (the only supported mode) is enforced
/// by that filter, installed once by the admin setup; the backend must not assume
/// it. The check is a read-only WFP query (no admin needed).
fn verify_egress_blocked() -> Result<(), String> {
    if unsafe { crate::wfp::block_installed() } {
        Ok(())
    } else {
        Err(
            "network is denied but the sandbox user's WFP egress-block filter is not installed; \
             run setup/sandbox-user.ps1 install (elevated) to restore it. \
             Refusing rather than run with open egress."
                .to_string(),
        )
    }
}

pub(crate) fn run_sandbox_user(policy: &Policy, command: &[String]) -> Result<RunOutcome, RunError> {
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let tag = format!("u{}.{}", std::process::id(), COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
    unsafe {
        if let Some(note) = recover_orphans() {
            eprintln!("tartaros: {note}");
        }
        let user = SandboxUser::load().map_err(err)?;
        // This tier supports only "network denied" (validate refuses the rest),
        // enforced by the per-SID firewall rule from setup. Verify it is present
        // rather than assume it.
        verify_egress_blocked().map_err(err)?;
        prepare(policy)?;
        let program = Path::new(&command[0]);
        let program = program.is_absolute().then_some(program);
        let mut journal = Journal::open(&tag, None).map_err(err)?;
        let made = match make_placeholders(policy, &mut journal) {
            Ok(m) => m,
            Err(e) => {
                journal.finish();
                return Err(err(e));
            }
        };
        let saved = match apply_plan(policy, program, &mut journal, |path, grant| apply_user(path, &user.sid_str, grant)) {
            Ok(s) => s,
            Err(e) => {
                remove_placeholders(&made);
                journal.finish();
                return Err(e);
            }
        };
        let outcome = spawn_user(policy, command, &user, &tag);
        let failed = restore(saved);
        if !failed.is_empty() {
            // The journal stays: the next run retries the restore.
            return Err(err(format!("run finished but ACL restore failed:{}", restore_note(&failed))));
        }
        warn_kept(&remove_placeholders(&made));
        journal.finish();
        outcome
    }
}

/// The job every run lives in: kill-on-close plus the policy's caps. No
/// BREAKAWAY_OK, so nothing the agent starts can leave it.
unsafe fn make_job(policy: &Policy) -> Result<HANDLE, RunError> {
    let job = CreateJobObjectW(null(), null());
    if job.is_null() {
        return Err(err(format!("CreateJobObject: {}", std::io::Error::last_os_error())));
    }
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = zeroed();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if let Some(b) = policy.max_memory_bytes {
        limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
        limits.JobMemoryLimit = b as usize;
    }
    if let Some(n) = policy.max_processes {
        limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        limits.BasicLimitInformation.ActiveProcessLimit = n.min(u32::MAX as u64) as u32;
    }
    if let Some(s) = policy.max_cpu_secs {
        limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_TIME;
        limits.BasicLimitInformation.PerJobUserTimeLimit = (s as i64) * 10_000_000;
    }
    if SetInformationJobObject(
        job,
        JobObjectExtendedLimitInformation,
        &limits as *const _ as *const c_void,
        size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
    ) == 0
    {
        let e = std::io::Error::last_os_error();
        CloseHandle(job);
        return Err(err(format!("SetInformationJobObject: {e}")));
    }
    Ok(job)
}

fn command_line(command: &[String]) -> String {
    let mut cmdline = String::new();
    for (i, a) in command.iter().enumerate() {
        if i > 0 {
            cmdline.push(' ');
        }
        quote(a, &mut cmdline);
    }
    cmdline
}

/// The working directory: the first writable root that is a directory (a root
/// may be a single file; then its parent).
fn working_dir(policy: &Policy) -> Option<Vec<u16>> {
    policy
        .writable_roots
        .iter()
        .find(|p| p.is_dir())
        .cloned()
        .or_else(|| policy.writable_roots.first().and_then(|p| p.parent().map(Path::to_path_buf)))
        .map(|p| native(&p))
}

/// Wait for the process, enforcing the policy timeout; returns its exit code.
unsafe fn wait_exit(policy: &Policy, job: HANDLE, process: HANDLE) -> i32 {
    let wait_ms = policy.timeout.map_or(INFINITE, |t| t.as_millis().min(u32::MAX as u128 - 1) as u32);
    if WaitForSingleObject(process, wait_ms) == WAIT_TIMEOUT {
        TerminateJobObject(job, EXIT_TIMEOUT as u32);
        WaitForSingleObject(process, INFINITE);
        EXIT_TIMEOUT
    } else {
        let mut code: u32 = 0;
        GetExitCodeProcess(process, &mut code);
        code as i32
    }
}

/// Launch as the sandbox user: CreateProcessWithLogonW (the only logon-and-spawn
/// call a non-admin may make), suspended, on a private desktop, assigned to the
/// job before it runs a single instruction.
unsafe fn spawn_user(policy: &Policy, command: &[String], user: &SandboxUser, tag: &str) -> Result<RunOutcome, RunError> {
    let job = make_job(policy)?;
    // A process of another user, created through seclogon, also needs
    // WINSTA_EXITWINDOWS (0x40) on the shared window station or its user32 init
    // fails with 0xC0000142 (measured; the AppContainer does not).
    let mut desk = match private_desktop(user.sid, tag, 0x1 | 0x2 | 0x20 | 0x40 | READ_CONTROL) {
        Ok(d) => d,
        Err(e) => {
            CloseHandle(job);
            return Err(err(format!("private desktop: {e}")));
        }
    };
    let mut si: STARTUPINFOW = zeroed();
    si.cb = size_of::<STARTUPINFOW>() as u32;
    si.dwFlags = STARTF_USESTDHANDLES;
    for (which, slot) in [
        (STD_INPUT_HANDLE, &mut si.hStdInput),
        (STD_OUTPUT_HANDLE, &mut si.hStdOutput),
        (STD_ERROR_HANDLE, &mut si.hStdError),
    ] {
        let h = GetStdHandle(which);
        if !h.is_null() && h as isize != -1 {
            SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
        }
        *slot = h;
    }
    si.lpDesktop = desk.lp.as_mut_ptr();

    // First hop: the runner, as the sandbox user. It re-launches the command
    // under a write-restricted token (see `sandbox_runner_main`).
    let runner = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.join(RUNNER_EXE)))
        .filter(|r| r.is_file())
        .ok_or_else(|| err(format!("{RUNNER_EXE} not found next to the current executable")));
    let runner = match runner {
        Ok(r) => r,
        Err(e) => {
            desk.close();
            CloseHandle(job);
            return Err(e);
        }
    };
    // CreateProcessWithLogonW caps the command line at 1024 characters, so the
    // command travels to the runner in RUNNER_CMDLINE_VAR (the runner takes it
    // out of its environment before starting the command).
    let cmdline = command_line(&[runner.to_string_lossy().into_owned(), "--".to_string()]);
    if std::env::var_os("TARTAROS_DEBUG").is_some() {
        eprintln!("[cmdline] {cmdline} (as {})", user.sid_str);
    }
    let runner_w = native(&runner);
    let mut cmdline_w = wide(OsStr::new(&cmdline));
    let env = env_block(policy, None, user.profile.as_deref(), Some((RUNNER_CMDLINE_VAR, &command_line(command))));
    let cwd = working_dir(policy);
    let domain = wide(OsStr::new("."));
    let mut pi: PROCESS_INFORMATION = zeroed();
    let created = CreateProcessWithLogonW(
        user.name.as_ptr(),
        domain.as_ptr(),
        user.password.as_ptr(),
        LOGON_WITH_PROFILE,
        runner_w.as_ptr(),
        cmdline_w.as_mut_ptr(),
        // No console of its own: a console program started as another user
        // cannot create one here; stdio goes through the inherited handles.
        CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
        env.as_ref().map_or(null(), |e| e.as_ptr() as *const c_void),
        cwd.as_ref().map_or(null(), |c| c.as_ptr()),
        &si,
        &mut pi,
    );
    if created == 0 {
        let e = std::io::Error::last_os_error();
        desk.close();
        CloseHandle(job);
        return Err(err(format!("CreateProcessWithLogon {}: {e}", command[0])));
    }
    if AssignProcessToJobObject(job, pi.hProcess) == 0 {
        let e = std::io::Error::last_os_error();
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        desk.close();
        CloseHandle(job);
        return Err(err(format!("AssignProcessToJobObject: {e}")));
    }
    ResumeThread(pi.hThread);
    let exit_code = wait_exit(policy, job, pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(job);
    desk.close();
    Ok(RunOutcome { exit_code })
}

/// The runner binary, installed next to whatever embeds this backend.
pub(crate) const RUNNER_EXE: &str = "tartaros-sbx-runner.exe";
/// The command line the runner starts (see `spawn_user`).
const RUNNER_CMDLINE_VAR: &str = "TARTAROS_SBX_CMDLINE";

/// Second hop, running as the sandbox user inside the job: start the command
/// with a WRITE_RESTRICTED copy of this token whose restricting SIDs are the
/// sandbox user's own and Everyone. Every write must then also be granted to
/// one of them; only the per-run grants (and the user's own profile) name the
/// user, so a directory that Authenticated Users or Users may write stays
/// read-only to the agent (one writable by Everyone does not). Reads are untouched (WRITE_RESTRICTED checks restricting SIDs on writes
/// only). Never returns: exits with the command's exit code.
pub(crate) fn sandbox_runner_main() -> ! {
    // The command line comes in RUNNER_CMDLINE_VAR (taken out of the
    // environment the command inherits), or after `--` when run by hand.
    let cmdline = match std::env::var(RUNNER_CMDLINE_VAR) {
        Ok(c) => {
            std::env::remove_var(RUNNER_CMDLINE_VAR);
            c
        }
        Err(_) => {
            let args: Vec<String> = std::env::args().collect();
            match args.iter().position(|a| a == "--") {
                Some(sep) => command_line(&args[sep + 1..]),
                None => String::new(),
            }
        }
    };
    if cmdline.is_empty() {
        eprintln!("tartaros-sbx-runner: usage: tartaros-sbx-runner -- COMMAND [ARGS]...");
        std::process::exit(125);
    }
    match unsafe { run_restricted(&cmdline) } {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("tartaros-sbx-runner: {e}");
            std::process::exit(125);
        }
    }
}

unsafe fn run_restricted(cmdline: &str) -> Result<i32, String> {
    let mut token: HANDLE = null_mut();
    if OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut token) == 0 {
        return Err(format!("OpenProcessToken: {}", std::io::Error::last_os_error()));
    }
    // This token's user SID: a restricting SID, and the default DACL's owner.
    let mut len = 0u32;
    GetTokenInformation(token, TokenUser, null_mut(), 0, &mut len);
    let mut buf = vec![0u8; len as usize];
    if GetTokenInformation(token, TokenUser, buf.as_mut_ptr() as *mut c_void, len, &mut len) == 0 {
        CloseHandle(token);
        return Err(format!("GetTokenInformation(TokenUser): {}", std::io::Error::last_os_error()));
    }
    let user = &*(buf.as_ptr() as *const TOKEN_USER);
    // Restricting SIDs: the sandbox user, and Everyone, without which the
    // loader cannot start a process at all (measured: user alone or user +
    // logon SID fail with 0xC0000142). Consequence: a path writable by Everyone
    // stays writable; one writable only by Authenticated Users or Users does not.
    let w = wide(OsStr::new("S-1-1-0"));
    let mut everyone: PSID = null_mut();
    if ConvertStringSidToSidW(w.as_ptr(), &mut everyone) == 0 {
        CloseHandle(token);
        return Err(format!("Everyone SID: {}", std::io::Error::last_os_error()));
    }
    let restrict = [
        SID_AND_ATTRIBUTES { Sid: user.User.Sid, Attributes: 0 },
        SID_AND_ATTRIBUTES { Sid: everyone, Attributes: 0 },
    ];
    let mut restricted: HANDLE = null_mut();
    let ok = CreateRestrictedToken(token, WRITE_RESTRICTED | DISABLE_MAX_PRIVILEGE, 0, null(), 0, null(), 2, restrict.as_ptr(), &mut restricted);
    LocalFree(everyone);
    CloseHandle(token);
    if ok == 0 {
        return Err(format!("CreateRestrictedToken: {}", std::io::Error::last_os_error()));
    }
    // Objects the command creates for itself (its process, threads, sections)
    // take the token's default DACL. Under WRITE_RESTRICTED a write to them must
    // also pass for a restricting SID, so the default DACL must name the user,
    // or the loader cannot initialize (0xC0000142, measured).
    let mut sid_s: *mut u16 = null_mut();
    ConvertSidToStringSidW(user.User.Sid, &mut sid_s);
    let sddl = format!("D:(A;;GA;;;{})(A;;GA;;;SY)", from_wide(sid_s));
    LocalFree(sid_s as *mut c_void);
    let ws = wide(OsStr::new(&sddl));
    let mut sd: *mut c_void = null_mut();
    if ConvertStringSecurityDescriptorToSecurityDescriptorW(ws.as_ptr(), SDDL_REVISION_1, &mut sd, null_mut()) == 0 {
        CloseHandle(restricted);
        return Err(format!("default DACL: {}", std::io::Error::last_os_error()));
    }
    let (mut present, mut defaulted) = (0, 0);
    let mut dacl: *mut ACL = null_mut();
    GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted);
    let dd = TOKEN_DEFAULT_DACL { DefaultDacl: dacl };
    let set = SetTokenInformation(restricted, TokenDefaultDacl, &dd as *const _ as *const c_void, size_of::<TOKEN_DEFAULT_DACL>() as u32);
    LocalFree(sd);
    if set == 0 {
        let e = std::io::Error::last_os_error();
        CloseHandle(restricted);
        return Err(format!("SetTokenInformation(TokenDefaultDacl): {e}"));
    }

    let mut si: STARTUPINFOW = zeroed();
    si.cb = size_of::<STARTUPINFOW>() as u32;
    si.dwFlags = STARTF_USESTDHANDLES;
    for (which, slot) in [
        (STD_INPUT_HANDLE, &mut si.hStdInput),
        (STD_OUTPUT_HANDLE, &mut si.hStdOutput),
        (STD_ERROR_HANDLE, &mut si.hStdError),
    ] {
        let h = GetStdHandle(which);
        if !h.is_null() && h as isize != -1 {
            SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
        }
        *slot = h;
    }
    let mut cmdline_w = wide(OsStr::new(cmdline));
    let mut pi: PROCESS_INFORMATION = zeroed();
    // Same desktop, environment, directory and job as this runner; no console of
    // its own (the runner has none to share), stdio through the handles.
    let created = CreateProcessAsUserW(restricted, null(), cmdline_w.as_mut_ptr(), null(), null(), 1, CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW, null(), null(), &si, &mut pi);
    let e = std::io::Error::last_os_error();
    CloseHandle(restricted);
    if created == 0 {
        return Err(format!("CreateProcessAsUser {cmdline}: {e}"));
    }
    CloseHandle(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    let mut code: u32 = 0;
    GetExitCodeProcess(pi.hProcess, &mut code);
    CloseHandle(pi.hProcess);
    Ok(code as i32)
}

pub(crate) fn is_elevated() -> bool {
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut e: TOKEN_ELEVATION = zeroed();
        let mut len = 0u32;
        let ok = GetTokenInformation(token, TokenElevation, &mut e as *mut _ as *mut c_void, size_of::<TOKEN_ELEVATION>() as u32, &mut len);
        CloseHandle(token);
        ok != 0 && e.TokenIsElevated != 0
    }
}
