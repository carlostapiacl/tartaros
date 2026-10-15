//! Win32 side of the backend. Everything here was first measured in the W0 spike.

use std::ffi::{c_void, OsStr};
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

use tartaros_core::{Policy, RunError, RunOutcome};
use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, WAIT_TIMEOUT,
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
    CreateProcessW, CreateProcessWithLogonW, GetCurrentProcess, LOGON_WITH_PROFILE, STARTUPINFOW, GetExitCodeProcess, InitializeProcThreadAttributeList,
    OpenProcessToken, ResumeThread, TerminateProcess, UpdateProcThreadAttribute,
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
unsafe fn private_desktop(sid: PSID, tag: &str) -> Result<Desk, String> {
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
    // Own window station: full access. Shared one: enumerate, read attributes,
    // global atoms (what user32 init needs), nothing else.
    let winsta_mask = if own_winsta { GENERIC_ALL } else { 0x1 | 0x2 | 0x20 | READ_CONTROL };
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
fn env_block(policy: &Policy, temp: Option<&Path>, profile: Option<&Path>) -> Option<Vec<u16>> {
    let mut vars: Vec<(String, String)> = match policy.child_env() {
        None => return None, // inherit_env: the caller opted into full passthrough
        Some(v) => v,
    };
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
        let container = Container::create(&tag).map_err(err)?;
        prepare(policy)?;
        let program = Path::new(&command[0]);
        let program = program.is_absolute().then_some(program);

        let saved = apply_plan(policy, program, |path, grant| apply(path, &container.sid_str, grant))?;

        let outcome = spawn(policy, command, &container, &tag);
        let failed = restore(saved);
        drop(container);
        if !failed.is_empty() {
            return Err(err(format!("run finished but ACL restore failed:{}", restore_note(&failed))));
        }
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
    apply_one: impl Fn(&Path, Grant) -> Result<Saved, String>,
) -> Result<Vec<Saved>, RunError> {
    let mut saved = Vec::new();
    let debug = std::env::var_os("TARTAROS_DEBUG").is_some();
    for (path, grant) in crate::acl_plan(policy, program) {
        if debug {
            eprintln!("[acl] {grant:?} {}", path.display());
        }
        match apply_one(&path, grant) {
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

    let mut desk = match private_desktop(c.sid, tag) {
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
    let env = env_block(policy, temp.as_deref(), None);
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
        let mut password: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        password.push(0);
        for b in bytes.iter_mut() {
            std::ptr::write_volatile(b, 0);
        }
        LocalFree(out.pbData as *mut c_void);
        let mut sid: PSID = null_mut();
        let ws = wide(OsStr::new(&sid_str));
        if ConvertStringSidToSidW(ws.as_ptr(), &mut sid) == 0 {
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

pub(crate) fn run_sandbox_user(policy: &Policy, command: &[String]) -> Result<RunOutcome, RunError> {
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let tag = format!("u{}.{}", std::process::id(), COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
    unsafe {
        let user = SandboxUser::load().map_err(err)?;
        prepare(policy)?;
        let program = Path::new(&command[0]);
        let program = program.is_absolute().then_some(program);
        let saved = apply_plan(policy, program, |path, grant| apply_user(path, &user.sid_str, grant))?;
        let outcome = spawn_user(policy, command, &user, &tag);
        let failed = restore(saved);
        if !failed.is_empty() {
            return Err(err(format!("run finished but ACL restore failed:{}", restore_note(&failed))));
        }
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
    let mut desk = match private_desktop(user.sid, tag) {
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

    let cmdline = command_line(command);
    if std::env::var_os("TARTAROS_DEBUG").is_some() {
        eprintln!("[cmdline] {cmdline} (as {})", user.sid_str);
    }
    let mut cmdline_w = wide(OsStr::new(&cmdline));
    let env = env_block(policy, None, user.profile.as_deref());
    let cwd = working_dir(policy);
    let domain = wide(OsStr::new("."));
    let mut pi: PROCESS_INFORMATION = zeroed();
    let created = CreateProcessWithLogonW(
        user.name.as_ptr(),
        domain.as_ptr(),
        user.password.as_ptr(),
        LOGON_WITH_PROFILE,
        null(),
        cmdline_w.as_mut_ptr(),
        CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
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
