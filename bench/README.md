# Benchmark — conformance suite for agent sandboxes

The measured basis for seisin-sandbox's claims: a set of checks any agent
sandbox either passes or fails, run against the real binaries.

- control (writes land in the workspace, not in HOME)
- `.git/hooks` protected at the first level AND in nested repos
- a deny survives renaming an ancestor directory
- no cross-process environment read (macOS KERN_PROCARGS2, Linux /proc)
- exit status on signal death; a single SIGINT; descendants reaped

> These checks are being turned into contracts in `security-bench/`.
