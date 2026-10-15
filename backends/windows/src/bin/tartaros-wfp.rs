//! Admin-only helper (invoked by setup/sandbox-user.ps1) that installs or removes
//! the per-SID WFP egress filters for the sandbox-user tier. Not used at run time.
//!
//! ```text
//! tartaros-wfp install <sid> [--allow-loopback-port <port>]
//! tartaros-wfp uninstall
//! tartaros-wfp check            # exit 0 if the block filter is installed
//! ```

fn main() {
    #[cfg(windows)]
    {
        std::process::exit(tartaros_windows::wfp_main(std::env::args().skip(1).collect()));
    }
    #[cfg(not(windows))]
    {
        eprintln!("tartaros-wfp only runs on Windows");
        std::process::exit(2);
    }
}
