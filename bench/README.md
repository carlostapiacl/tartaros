# Benchmark — conformance suite for agent sandboxes

The measured basis for tartaros's claims: a set of checks any agent
sandbox either passes or fails, run against the real binaries.

- control (writes land in the workspace, not in HOME)
- `.git/hooks` protected at the first level AND in nested repos
- a deny survives renaming an ancestor directory
- no cross-process environment read (Linux /proc; on macOS a known gap, KERN_PROCARGS2)
- exit status on signal death; a single SIGINT; descendants reaped

> These checks now live as contracts in [`security-bench/corpus/`](../security-bench/corpus/),
> and the cross-sandbox runs in [`security-bench/comparison/`](../security-bench/comparison/).
