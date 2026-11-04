//! A program that reads macOS preferences starts under tartaros.
//!
//! CoreFoundation reads three POSIX shared memory segments to tell whether its
//! cached preferences are current. Denied, `CFPreferencesAppSynchronize` returns
//! false once a value has been read, and a program that treats that as fatal does
//! not start: Codex CLI 0.166 stopped with "Failed to synchronize managed
//! preferences". The order matters: synchronizing before reading passes under
//! the old profile, so this reads first, as Codex does.
//!
//! The child is this same test binary, run under tartaros by the parent test.
#![cfg(target_os = "macos")]

use std::ffi::{c_char, c_int, c_void, CString};
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_tartaros");
const OTHER_SEGMENT: &str = "TARTAROS_TEST_OTHER_SEGMENT";
const CHILDREN: [&str; 2] = ["child_reads_then_synchronizes", "child_cannot_write_or_reach_other_segments"];

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFStringCreateWithCString(alloc: *const c_void, s: *const c_char, encoding: u32) -> *const c_void;
    fn CFPreferencesCopyAppValue(key: *const c_void, app: *const c_void) -> *const c_void;
    fn CFPreferencesAppSynchronize(app: *const c_void) -> u8;
}

fn cf_string(s: &str) -> *const c_void {
    const UTF8: u32 = 0x0800_0100;
    let s = CString::new(s).unwrap();
    unsafe { CFStringCreateWithCString(std::ptr::null(), s.as_ptr(), UTF8) }
}

/// Opens a segment and closes it; the errno when it was refused.
fn open_segment(name: &str, flags: c_int) -> Result<(), i32> {
    let name = CString::new(name).unwrap();
    let fd = unsafe { libc::shm_open(name.as_ptr(), flags, 0o600 as libc::c_uint) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
    }
    unsafe { libc::close(fd) };
    Ok(())
}

fn user_segment() -> String {
    format!("apple.cfprefs.{}v1", unsafe { libc::getuid() })
}

#[test]
#[ignore = "the child of preferences_are_readable_and_nothing_else_is"]
fn child_reads_then_synchronizes() {
    let app = cf_string("org.tartaros.test.preferences");
    unsafe {
        CFPreferencesCopyAppValue(cf_string("absent"), app);
        assert_ne!(CFPreferencesAppSynchronize(app), 0, "CFPreferencesAppSynchronize failed");
    }
}

#[test]
#[ignore = "the child of preferences_are_readable_and_nothing_else_is"]
fn child_cannot_write_or_reach_other_segments() {
    for name in ["apple.cfprefs.daemonv1", user_segment().as_str(), "apple.shm.notification_center"] {
        assert_eq!(open_segment(name, libc::O_RDONLY), Ok(()), "read {name}");
        assert_eq!(open_segment(name, libc::O_RDWR), Err(libc::EPERM), "write {name}");
    }
    let new = format!("apple.cfprefs.tt-new-{}", std::process::id());
    assert_eq!(open_segment(&new, libc::O_RDWR | libc::O_CREAT), Err(libc::EPERM), "create");
    let other = std::env::var(OTHER_SEGMENT).unwrap();
    assert_eq!(open_segment(&other, libc::O_RDONLY), Err(libc::EPERM), "read a segment not listed");
}

#[test]
fn preferences_are_readable_and_nothing_else_is() {
    let dir = std::env::temp_dir().join(format!("tartaros-preferences-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // A segment that exists, so a refusal below is the profile and not ENOENT.
    // Under the prefix a wider rule would open, and within the 31 characters macOS
    // allows a segment name.
    let other = format!("apple.cfprefs.tt-oth-{}", std::process::id());
    open_segment(&other, libc::O_RDWR | libc::O_CREAT).unwrap();

    let me = std::env::current_exe().unwrap();
    let mut failures = Vec::new();
    for child in CHILDREN {
        let out = Command::new(BIN)
            .arg("run").arg("--inherit-env").arg("--write").arg(&dir)
            .arg("--").arg(&me)
            .args(["--ignored", "--exact", child, "--nocapture"])
            .env(OTHER_SEGMENT, &other)
            .output()
            .unwrap();
        if !out.status.success() {
            failures.push(format!("{child}: {}", String::from_utf8_lossy(&out.stderr)));
        }
    }

    let name = CString::new(other).unwrap();
    unsafe { libc::shm_unlink(name.as_ptr()) };
    let _ = std::fs::remove_dir_all(dir);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
