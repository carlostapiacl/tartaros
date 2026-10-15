//! WFP (Windows Filtering Platform) egress control for the sandbox-user tier,
//! installed once by the admin setup and torn down by it.
//!
//! The Windows *firewall* (the `New-NetFirewallRule`/netsh layer) exempts
//! loopback, so it cannot keep a confined user off `127.0.0.1`. A raw WFP filter
//! at `ALE_AUTH_CONNECT` does see loopback, so this installs persistent filters
//! scoped to the sandbox user's SID:
//!
//! - **block mode:** deny every outbound connect by that SID, on IPv4 and IPv6,
//!   loopback included.
//! - **broker mode (`--allow-loopback-port P`):** additionally permit that SID to
//!   connect to `127.0.0.1:P` over TCP (the egress broker), at a higher weight, so
//!   the agent reaches the broker and nothing else.
//!
//! Every object has a fixed GUID, so teardown is `DeleteByKey` with no
//! enumeration. The filters are persistent (survive reboot) and owned by our
//! provider/sublayer; `uninstall` removes filters, then the sublayer, then the
//! provider.
#![cfg(windows)]

use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::ptr::{null, null_mut};

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{HANDLE, LocalFree};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};

// Fixed keys for our objects. Generated once; constant so teardown needs no
// enumeration. (tartaros WFP: provider, sublayer, and the four filters.)
const PROVIDER_KEY: GUID = GUID::from_u128(0x7a17a2c0_1e4d_4d33_9b0e_7a17a2c01e4d);
const SUBLAYER_KEY: GUID = GUID::from_u128(0x7a17a2c0_1e4d_4d33_9b0e_7a17a2c01e4e);
const F_BLOCK_V4: GUID = GUID::from_u128(0x7a17a2c0_1e4d_4d33_9b0e_7a17a2c01e50);
const F_BLOCK_V6: GUID = GUID::from_u128(0x7a17a2c0_1e4d_4d33_9b0e_7a17a2c01e51);
const F_PERMIT_V4: GUID = GUID::from_u128(0x7a17a2c0_1e4d_4d33_9b0e_7a17a2c01e52);
const FILTER_KEYS: [GUID; 4] = [F_BLOCK_V4, F_BLOCK_V6, F_PERMIT_V4, GUID::from_u128(0x7a17a2c0_1e4d_4d33_9b0e_7a17a2c01e53)];

const WEIGHT_BLOCK: u8 = 5;
const WEIGHT_PERMIT: u8 = 9;

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

fn check(rc: u32, what: &str) -> Result<(), String> {
    if rc == 0 {
        Ok(())
    } else {
        Err(format!("{what}: FWP error 0x{rc:08x}"))
    }
}

/// A self-relative security descriptor whose DACL grants the SID, for an
/// `ALE_USER_ID` condition (the engine access-checks the connecting token
/// against it). `G:` is required or `AccessCheck` rejects the SD.
struct UserSd {
    sd: *mut c_void,
    len: u32,
}
impl UserSd {
    unsafe fn new(sid: &str) -> Result<UserSd, String> {
        let sddl = wide(&format!("O:LSG:LSD:(A;;CC;;;{sid})"));
        let mut sd: *mut c_void = null_mut();
        let mut len = 0u32;
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, &mut len) == 0 {
            return Err(format!("bad SID {sid}: {}", std::io::Error::last_os_error()));
        }
        Ok(UserSd { sd, len })
    }
    /// The self-relative SD wrapped as the byte blob an SD-typed condition wants,
    /// with its real length (the engine rejects a zero-length SD blob, 0x53a).
    fn blob(&self) -> FWP_BYTE_BLOB {
        FWP_BYTE_BLOB { size: self.len, data: self.sd as *mut u8 }
    }
}
impl Drop for UserSd {
    fn drop(&mut self) {
        unsafe { LocalFree(self.sd) };
    }
}

unsafe fn open_engine() -> Result<HANDLE, String> {
    let mut h: HANDLE = null_mut();
    // Persistent (non-dynamic) session: the objects we add outlive the process.
    let session: FWPM_SESSION0 = std::mem::zeroed();
    check(
        FwpmEngineOpen0(null(), RPC_C_AUTHN_WINNT, null(), &session, &mut h),
        "FwpmEngineOpen0",
    )?;
    Ok(h)
}

fn display(name: &mut Vec<u16>) -> FWPM_DISPLAY_DATA0 {
    FWPM_DISPLAY_DATA0 { name: name.as_mut_ptr(), description: null_mut() }
}

/// One `ALE_USER_ID` == `sd` condition, reused by every filter.
fn cond_user(sd: &mut FWP_BYTE_BLOB) -> FWPM_FILTER_CONDITION0 {
    let mut v: FWP_CONDITION_VALUE0 = unsafe { std::mem::zeroed() };
    v.r#type = FWP_SECURITY_DESCRIPTOR_TYPE;
    v.Anonymous.sd = sd as *mut FWP_BYTE_BLOB;
    FWPM_FILTER_CONDITION0 { fieldKey: FWPM_CONDITION_ALE_USER_ID, matchType: FWP_MATCH_EQUAL, conditionValue: v }
}

fn cond_u8(field: GUID, val: u8) -> FWPM_FILTER_CONDITION0 {
    let mut v: FWP_CONDITION_VALUE0 = unsafe { std::mem::zeroed() };
    v.r#type = FWP_UINT8;
    v.Anonymous.uint8 = val;
    FWPM_FILTER_CONDITION0 { fieldKey: field, matchType: FWP_MATCH_EQUAL, conditionValue: v }
}

fn cond_u16(field: GUID, val: u16) -> FWPM_FILTER_CONDITION0 {
    let mut v: FWP_CONDITION_VALUE0 = unsafe { std::mem::zeroed() };
    v.r#type = FWP_UINT16;
    v.Anonymous.uint16 = val;
    FWPM_FILTER_CONDITION0 { fieldKey: field, matchType: FWP_MATCH_EQUAL, conditionValue: v }
}

fn cond_v4(field: GUID, mask: &mut FWP_V4_ADDR_AND_MASK) -> FWPM_FILTER_CONDITION0 {
    let mut v: FWP_CONDITION_VALUE0 = unsafe { std::mem::zeroed() };
    v.r#type = FWP_V4_ADDR_MASK;
    v.Anonymous.v4AddrMask = mask as *mut FWP_V4_ADDR_AND_MASK;
    FWPM_FILTER_CONDITION0 { fieldKey: field, matchType: FWP_MATCH_EQUAL, conditionValue: v }
}

fn weight(w: u8) -> FWP_VALUE0 {
    let mut v: FWP_VALUE0 = unsafe { std::mem::zeroed() };
    v.r#type = FWP_UINT8;
    v.Anonymous.uint8 = w;
    v
}

#[allow(clippy::too_many_arguments)]
unsafe fn add_filter(
    engine: HANDLE,
    key: GUID,
    name: &str,
    layer: GUID,
    action: u32,
    w: u8,
    conditions: &mut [FWPM_FILTER_CONDITION0],
) -> Result<(), String> {
    let mut nm = wide(name);
    let mut f: FWPM_FILTER0 = std::mem::zeroed();
    f.filterKey = key;
    f.displayData = display(&mut nm);
    f.flags = FWPM_FILTER_FLAG_PERSISTENT;
    f.providerKey = &PROVIDER_KEY as *const GUID as *mut GUID;
    f.layerKey = layer;
    f.subLayerKey = SUBLAYER_KEY;
    f.weight = weight(w);
    f.numFilterConditions = conditions.len() as u32;
    f.filterCondition = conditions.as_mut_ptr();
    f.action.r#type = action;
    let mut id = 0u64;
    check(FwpmFilterAdd0(engine, &f, null_mut(), &mut id), &format!("FwpmFilterAdd0({name})"))
}

/// Install the persistent per-SID egress filters. `broker_port`: Some(p) permits
/// TCP to 127.0.0.1:p (the broker); None blocks everything.
pub unsafe fn install(sid: &str, broker_port: Option<u16>) -> Result<(), String> {
    let user = UserSd::new(sid)?;
    let engine = open_engine()?;
    let r = (|| {
        check(FwpmTransactionBegin0(engine, 0), "FwpmTransactionBegin0")?;

        let mut pname = wide("tartaros sandbox egress");
        let mut provider: FWPM_PROVIDER0 = std::mem::zeroed();
        provider.providerKey = PROVIDER_KEY;
        provider.displayData = display(&mut pname);
        provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
        // Adding an existing provider returns FWP_E_ALREADY_EXISTS (0x80320009);
        // treat that as success so install is idempotent.
        let rc = FwpmProviderAdd0(engine, &provider, null_mut());
        if rc != 0 && rc != 0x8032_0009 {
            return check(rc, "FwpmProviderAdd0");
        }

        let mut sname = wide("tartaros sandbox egress");
        let mut sublayer: FWPM_SUBLAYER0 = std::mem::zeroed();
        sublayer.subLayerKey = SUBLAYER_KEY;
        sublayer.displayData = display(&mut sname);
        sublayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
        sublayer.providerKey = &PROVIDER_KEY as *const GUID as *mut GUID;
        sublayer.weight = 0x100;
        let rc = FwpmSubLayerAdd0(engine, &sublayer, null_mut());
        if rc != 0 && rc != 0x8032_0009 {
            return check(rc, "FwpmSubLayerAdd0");
        }

        // Block every outbound connect by this SID, v4 and v6 (loopback too).
        let mut blob = user.blob();
        let mut c = [cond_user(&mut blob)];
        add_filter(engine, F_BLOCK_V4, "tartaros block egress v4", FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWP_ACTION_BLOCK, WEIGHT_BLOCK, &mut c)?;
        let mut blob6 = user.blob();
        let mut c6 = [cond_user(&mut blob6)];
        add_filter(engine, F_BLOCK_V6, "tartaros block egress v6", FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWP_ACTION_BLOCK, WEIGHT_BLOCK, &mut c6)?;

        if let Some(port) = broker_port {
            // Permit TCP to 127.0.0.1:port for this SID, above the block.
            let mut loopback = FWP_V4_ADDR_AND_MASK { addr: 0x7f00_0001, mask: 0xffff_ffff };
            let mut pblob = user.blob();
            let mut pc = [
                cond_user(&mut pblob),
                cond_u8(FWPM_CONDITION_IP_PROTOCOL, 6), // TCP
                cond_u16(FWPM_CONDITION_IP_REMOTE_PORT, port),
                cond_v4(FWPM_CONDITION_IP_REMOTE_ADDRESS, &mut loopback),
            ];
            add_filter(engine, F_PERMIT_V4, "tartaros permit broker v4", FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWP_ACTION_PERMIT, WEIGHT_PERMIT, &mut pc)?;
        }

        check(FwpmTransactionCommit0(engine), "FwpmTransactionCommit0")
    })();
    if r.is_err() {
        FwpmTransactionAbort0(engine);
    }
    FwpmEngineClose0(engine);
    r
}

/// Remove every object this module installs. Idempotent: a missing object
/// (FWP_E_FILTER_NOT_FOUND 0x80320003 / not found) is not an error.
pub unsafe fn uninstall() -> Result<(), String> {
    let engine = open_engine()?;
    let r = (|| {
        check(FwpmTransactionBegin0(engine, 0), "FwpmTransactionBegin0")?;
        // Not-found is success for an idempotent uninstall: filter 0x80320003,
        // provider 0x80320005, sublayer 0x80320007.
        let ok_missing = |rc: u32| if matches!(rc, 0 | 0x8032_0003 | 0x8032_0005 | 0x8032_0007) { 0 } else { rc };
        for k in &FILTER_KEYS {
            check(ok_missing(FwpmFilterDeleteByKey0(engine, k)), "FwpmFilterDeleteByKey0")?;
        }
        check(ok_missing(FwpmSubLayerDeleteByKey0(engine, &SUBLAYER_KEY)), "FwpmSubLayerDeleteByKey0")?;
        check(ok_missing(FwpmProviderDeleteByKey0(engine, &PROVIDER_KEY)), "FwpmProviderDeleteByKey0")?;
        check(FwpmTransactionCommit0(engine), "FwpmTransactionCommit0")
    })();
    if r.is_err() {
        FwpmTransactionAbort0(engine);
    }
    FwpmEngineClose0(engine);
    r
}

/// Whether the v4 block filter is installed (the runtime egress check).
pub unsafe fn block_installed() -> bool {
    let engine = match open_engine() {
        Ok(e) => e,
        Err(_) => return false,
    };
    let mut f: *mut FWPM_FILTER0 = null_mut();
    let rc = FwpmFilterGetByKey0(engine, &F_BLOCK_V4, &mut f);
    let present = rc == 0 && !f.is_null();
    if !f.is_null() {
        FwpmFreeMemory0(&mut (f as *mut c_void));
    }
    FwpmEngineClose0(engine);
    present
}
