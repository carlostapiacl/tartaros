//! Second hop of the Windows sandbox-user tier: started as the sandbox user by
//! the backend, it runs the command under a write-restricted token.

fn main() {
    tartaros_windows::sandbox_runner_main()
}
