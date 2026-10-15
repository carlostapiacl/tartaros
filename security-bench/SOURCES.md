# Contract sources

Most scenarios in `corpus/` are original to TartarOS. The ones below are derived
from a guarantee asserted in another sandbox's public test suite, re-expressed as
an attack + legitimate control + real-effect assertion. Each keeps a `source` field
and the attribution here; no upstream test code was copied.

| upstream | license | scenarios |
|---|---|---|
| anthropics/sandbox-runtime | Apache-2.0 | 75 |
| nolabs-ai/nono | Apache-2.0 | 13 |
| openai/codex | Apache-2.0 | 10 |
| containers/bubblewrap | LGPL-2.1+ (guarantee only) | 1 |


## sandbox-runtime

- `filesystem-rm-under-read-deny-ancestor` — anthropics/sandbox-runtime test/sandbox/allow-read.test.ts (Apache-2.0)
- `filesystem-write-deny-absent-path` — anthropics/sandbox-runtime test/sandbox/deny-path-made-meanwhile.test.ts (Apache-2.0)
- `filesystem-write-deny-rename-bypass` — anthropics/sandbox-runtime test/sandbox/macos-seatbelt.test.ts (Apache-2.0)
- `filesystem-write-deny-via-symlink-spelling` — anthropics/sandbox-runtime test/sandbox/deny-order-independence.test.ts, test/sandbox/read-deny-glob.test.ts (Apache-2.0)
- `fs-dangling-symlink-create-outside` — anthropics/sandbox-runtime test/sandbox/integration.test.ts (Apache-2.0)
- `fs-hardlink-create-write-out` — anthropics/sandbox-runtime test/sandbox/write-through-links.test.ts (Apache-2.0)
- `fs-hardlink-widen-write` — anthropics/sandbox-runtime test/sandbox/integration.test.ts (Apache-2.0)
- `fs-symlink-dangling-create` — anthropics/sandbox-runtime test/sandbox/write-through-links.test.ts (Apache-2.0)
- `fs-symlink-file-out-agent-made` — anthropics/sandbox-runtime test/sandbox/write-through-links.test.ts (Apache-2.0)
- `fs-symlink-rename-out` — anthropics/sandbox-runtime test/sandbox/write-through-links.test.ts (Apache-2.0)
- `fs-writable-root-symlink-out` — anthropics/sandbox-runtime test/sandbox/symlink-write-path.test.ts (Apache-2.0)
- `fs-writable-root-symlink-parent` — anthropics/sandbox-runtime test/sandbox/symlink-boundary.test.ts (Apache-2.0)
- `isolation-no-effective-caps` — anthropics/sandbox-runtime test/sandbox/pid-namespace-isolation.test.ts (Apache-2.0)
- `isolation-no-new-privs` — anthropics/sandbox-runtime test/sandbox/integration.test.ts (Apache-2.0)
- `isolation-proc-mem-launcher-denied` — anthropics/sandbox-runtime test/sandbox/pid-namespace-isolation.test.ts (Apache-2.0)
- `isolation-process-info-environ` — anthropics/sandbox-runtime test/sandbox/pid-namespace-isolation.test.ts (Apache-2.0)
- `isolation-ptrace-launcher-denied` — anthropics/sandbox-runtime test/sandbox/pid-namespace-isolation.test.ts (Apache-2.0)
- `isolation-root-mount-bypass-denied` — anthropics/sandbox-runtime test/docker-weak-sandbox.test.ts (Apache-2.0)
- `lifecycle-background-reaped-on-exit` — anthropics/sandbox-runtime test/sandbox/integration.test.ts and pid-namespace-isolation.test.ts (Apache-2.0)
- `lifecycle-exit-status-forwarded` — anthropics/sandbox-runtime test/sandbox/pid-namespace-isolation.test.ts and integration.test.ts (Apache-2.0)
- `network-egress-public-denied` — anthropics/sandbox-runtime test/sandbox/macos-allow-local-binding.test.ts (Apache-2.0)
- `network-local-bind-denied` — anthropics/sandbox-runtime test/sandbox/macos-allow-local-binding.test.ts (Apache-2.0)
- `network-socket-domain-high-bits` — anthropics/sandbox-runtime test/sandbox/seccomp-vsock-block.test.ts (Apache-2.0)
- `read-allow-inside-deny-writable-ancestor` — anthropics/sandbox-runtime test/sandbox/allow-read.test.ts (Apache-2.0)
- `read-allow-symlink-into-deny` — anthropics/sandbox-runtime test/sandbox/linux-mount-plan-record.test.ts (Apache-2.0)
- `read-allow-symlink-no-reopen` — anthropics/sandbox-runtime test/sandbox/read-deny-glob.test.ts, test/sandbox/read-list-precedence.test.ts (Apache-2.0)
- `read-allow-trailing-slash-nested-deny` — anthropics/sandbox-runtime test/sandbox/trailing-slash-deny-spellings.test.ts (Apache-2.0)
- `read-allow-writable-carveout-trailing-slash` — anthropics/sandbox-runtime test/sandbox/trailing-slash-deny-spellings.test.ts (Apache-2.0)
- `read-deny-alt-spelling` — anthropics/sandbox-runtime test/sandbox/linux-one-mount-per-destination.test.ts (Apache-2.0)
- `read-deny-backslash-name` — anthropics/sandbox-runtime test/sandbox/names-with-a-backslash.test.ts (Apache-2.0)
- `read-deny-bracket-dir` — anthropics/sandbox-runtime test/sandbox/brackets-that-spell-no-set.test.ts (Apache-2.0)
- `read-deny-given-via-symlink` — anthropics/sandbox-runtime test/sandbox/read-list-precedence.test.ts, test/sandbox/read-deny-glob.test.ts (Apache-2.0)
- `read-deny-link-dotdot` — anthropics/sandbox-runtime test/sandbox/rules-through-links-on-every-runtime.test.ts (Apache-2.0)
- `read-deny-not-reopened-by-nested-writable` — anthropics/sandbox-runtime test/sandbox/default-write-paths.test.ts (Apache-2.0)
- `read-deny-root-carve-out` — anthropics/sandbox-runtime test/sandbox/allow-read.test.ts (Apache-2.0)
- `read-deny-symlink-entry` — anthropics/sandbox-runtime test/sandbox/linux-mount-plan-record.test.ts (Apache-2.0)
- `read-deny-symlinked-dir` — anthropics/sandbox-runtime test/sandbox/symlinked-deny-paths.test.ts (Apache-2.0)
- `read-deny-trailing-slash-nested-write-deny` — anthropics/sandbox-runtime test/sandbox/trailing-slash-deny-spellings.test.ts (Apache-2.0)
- `read-deny-under-write-deny` — anthropics/sandbox-runtime test/sandbox/readonly-deny-dir-binds.test.ts (Apache-2.0)
- `seccomp-io-uring-denied` — anthropics/sandbox-runtime test/sandbox/pid-namespace-isolation.test.ts (Apache-2.0)
- `seccomp-new-mount-api-denied` — anthropics/sandbox-runtime test/sandbox/linux-nested-userns.test.ts and seccomp-filter-generator.test.ts (Apache-2.0)
- `secrets-env-passthrough-selective` — anthropics/sandbox-runtime test/sandbox/credential-deny.test.ts (Apache-2.0)
- `secrets-env-scrub-common-tokens` — anthropics/sandbox-runtime test/sandbox/credential-deny.test.ts, credential-mask-env.test.ts, credential-mask.test.ts (Apache-2.0)
- `secrets-read-allow-symlink-into-deny` — anthropics/sandbox-runtime test/sandbox/linux-ancestor-pin.test.ts (Apache-2.0)
- `secrets-read-deny-after-chmod` — anthropics/sandbox-runtime test/sandbox/linux-ancestor-pin-errno.test.ts (Apache-2.0)
- `secrets-read-deny-also-write-denied` — anthropics/sandbox-runtime test/sandbox/wrap-with-sandbox.test.ts (Apache-2.0)
- `secrets-read-deny-case-fold` — anthropics/sandbox-runtime test/sandbox/allow-read.test.ts (Apache-2.0)
- `secrets-read-deny-clonefile` — anthropics/sandbox-runtime test/sandbox/allow-read.test.ts (Apache-2.0)
- `secrets-read-deny-firmlink` — anthropics/sandbox-runtime test/sandbox/allow-read.test.ts (Apache-2.0)
- `secrets-read-deny-rename-out` — anthropics/sandbox-runtime test/sandbox/read-list-precedence.test.ts, test/sandbox/allow-read.test.ts (Apache-2.0)
- `secrets-read-deny-single-file` — anthropics/sandbox-runtime test/sandbox/credential-deny.test.ts (Apache-2.0)
- `secrets-read-deny-symlinked-entry` — anthropics/sandbox-runtime test/sandbox/credential-deny.test.ts (Apache-2.0)
- `secrets-read-deny-under-write-denied-ancestor` — anthropics/sandbox-runtime test/sandbox/wrap-with-sandbox.test.ts (Apache-2.0)
- `trust-handoff-bracketed-root` — anthropics/sandbox-runtime test/sandbox/macos-literal-deny-brackets.test.ts (Apache-2.0)
- `trust-handoff-editor-dirs` — anthropics/sandbox-runtime test/sandbox/mandatory-deny-paths.test.ts (Apache-2.0)
- `trust-handoff-git-config` — anthropics/sandbox-runtime test/sandbox/mandatory-deny-paths.test.ts (Apache-2.0)
- `trust-handoff-git-config-move-aside` — anthropics/sandbox-runtime test/sandbox/linux-nested-userns.test.ts (Apache-2.0)
- `trust-handoff-gitignored-repo` — anthropics/sandbox-runtime test/sandbox/mandatory-deny-paths.test.ts (Apache-2.0)
- `trust-handoff-symlinked-claude-dir` — anthropics/sandbox-runtime test/sandbox/symlinked-deny-paths.test.ts (Apache-2.0)
- `trust-handoff-unreadable-at-compile` — anthropics/sandbox-runtime test/sandbox/mandatory-deny-paths.test.ts (Apache-2.0)
- `trust-handoff-worktree-gitfile` — anthropics/sandbox-runtime test/sandbox/mandatory-deny-paths.test.ts (Apache-2.0)
- `write-deny-absent-deep` — anthropics/sandbox-runtime test/sandbox/mandatory-deny-paths.test.ts (Apache-2.0)
- `write-deny-backslash-absent` — anthropics/sandbox-runtime test/sandbox/names-with-a-backslash.test.ts (Apache-2.0)
- `write-deny-covers-nested-root` — anthropics/sandbox-runtime test/sandbox/readonly-deny-dir-binds.test.ts (Apache-2.0)
- `write-deny-cut-short-hop` — anthropics/sandbox-runtime test/sandbox/rules-through-links-on-every-runtime.test.ts (Apache-2.0)
- `write-deny-dangling-link-target` — anthropics/sandbox-runtime test/sandbox/rules-through-links-on-every-runtime.test.ts (Apache-2.0)
- `write-deny-equals-root` — anthropics/sandbox-runtime test/sandbox/readonly-deny-dir-binds.test.ts (Apache-2.0)
- `write-deny-existing-file-chmod` — anthropics/sandbox-runtime test/sandbox/stale-mount-point.test.ts (Apache-2.0)
- `write-deny-glob-chars-dir` — anthropics/sandbox-runtime test/sandbox/literal-path-entries.test.ts (Apache-2.0)
- `write-deny-link-dotdot` — anthropics/sandbox-runtime test/sandbox/rules-through-links-on-every-runtime.test.ts (Apache-2.0)
- `write-deny-noncanonical-absent` — anthropics/sandbox-runtime test/sandbox/path-canonicalization.test.ts (Apache-2.0)
- `write-deny-symlinked-parent` — anthropics/sandbox-runtime test/sandbox/symlinked-deny-paths.test.ts (Apache-2.0)
- `write-deny-through-policy-symlink` — anthropics/sandbox-runtime test/sandbox/mandatory-deny-paths.test.ts (Apache-2.0)
- `write-deny-trailing-slash` — anthropics/sandbox-runtime test/sandbox/readonly-deny-dir-stubs.test.ts (Apache-2.0)
- `write-deny-under-dotdot-root` — anthropics/sandbox-runtime test/sandbox/literal-path-entries.test.ts (Apache-2.0)

## nono

- `filesystem-rename-into-territory` — nolabs-ai/nono crates/nono-cli/tests/execution_strategy_run.rs (Landlock Refer rename) (Apache-2.0)
- `filesystem-rename-out-of-territory` — nolabs-ai/nono crates/nono-cli/tests/execution_strategy_run.rs (same-FS rename / Landlock Refer, #1689) (Apache-2.0)
- `filesystem-single-file-grant` — nolabs-ai/nono tests/integration/test_child_tool_boundaries.sh (\
- `filesystem-truncate-outside` — nolabs-ai/nono tests/integration/test_system_paths.sh (\
- `filesystem-unlink-outside` — nolabs-ai/nono tests/integration/test_profiles.sh (\
- `filesystem-write-deny-unlink-recreate` — nolabs-ai/nono crates/nono-cli/tests/glob_deny_after_start_run.rs (deleted_and_recreated_file_stays_denied) (Apache-2.0)
- `isolation-seccomp-io-uring-denied` — nolabs-ai/nono crates/nono-cli/tests/execution_strategy_run.rs (cli_auto_block_net_uses_static_seccomp_baseline: \
- `lifecycle-effect-log-tamper` — nolabs-ai/nono tests/integration/test_sensitive_paths.sh (\
- `secrets-env-loader-injection-scrub` — nolabs-ai/nono tests/integration/test_env_sanitization.sh (LD_PRELOAD, LD_LIBRARY_PATH, DYLD_INSERT_LIBRARIES, PYTHONSTARTUP, NODE_OPTIONS, PERL5OPT) (Apache-2.0)
- `secrets-read-deny-dir-listing` — nolabs-ai/nono tests/integration/test_sensitive_paths.sh (\
- `secrets-read-deny-on-symlinked-path` — nolabs-ai/nono crates/nono-cli/tests/symlink_hop_run.rs (symlinked grants must resolve) (Apache-2.0)
- `secrets-read-deny-path-special-chars` — nolabs-ai/nono tests/integration/test_edge_cases.sh (\
- `secrets-read-deny-prefix-collision` — nolabs-ai/nono tests/integration/test_sensitive_paths.sh (\

## codex

- `filesystem-command-cwd-not-writable` — openai/codex codex-rs/exec/tests/suite/sandbox.rs::sandbox_distinguishes_command_and_policy_cwds (Apache-2.0)
- `filesystem-write-deny-symlink-alias` — openai/codex codex-rs/exec/tests/suite/seatbelt.rs::seatbelt_blocks_protected_reads_and_writes_through_symlink_aliases (Apache-2.0)
- `filesystem-write-deny-truncate-unlink` — openai/codex codex-rs/exec/tests/suite/seatbelt.rs::seatbelt_deny_globs_block_writes_to_existing_and_new_files (Apache-2.0)
- `filesystem-write-reallow-inside-deny` — openai/codex codex-rs/linux-sandbox/tests/suite/sandbox.rs::sandbox_reenables_writable_subpaths_under_unreadable_parents (Apache-2.0)
- `isolation-no-capabilities` — openai/codex codex-rs/linux-sandbox/tests/suite/sandbox.rs::sandboxed_command_has_no_effective_or_permitted_capabilities; idea also in containers/bubblewrap tests/test-run.sh \
- `isolation-pid1-reaper-filtered` — openai/codex codex-rs/linux-sandbox/tests/suite/managed_proxy.rs::sandboxed_commands_have_a_seccomp_filtered_namespace_reaper and ::namespace_reaper_collects_orphaned_descendants (Apache-2.0)
- `network-tcp-external-denied` — openai/codex codex-rs/linux-sandbox/tests/suite/sandbox.rs::sandbox_blocks_curl and codex-rs/sandboxing/src/seatbelt_network_tests.rs::external_dns_child (Apache-2.0)
- `secrets-home-credentials-in-writable` — openai/codex codex-rs/sandboxing/src/seatbelt_tests.rs::seatbelt_protects_aws_in_extra_writable_home and codex-rs/linux-sandbox/tests/suite/sandbox.rs::sandbox_blocks_metadata_writes_inside_writable_root (Apache-2.0)
- `secrets-proc-host-process-links` — openai/codex codex-rs/linux-sandbox/tests/suite/daemon_sockets_tests.rs::daemon_sockets_are_hidden_with_network_and_tmp_write_grants (host-proc mode) (Apache-2.0)
- `trust-handoff-gitdir-pointer` — openai/codex codex-rs/linux-sandbox/tests/suite/nested_metadata_tests.rs::workspace_write_protects_resolved_gitdir_in_another_writable_root and codex-rs/sandboxing/src/seatbelt_tests.rs::workspace_write_protects_linked_worktree_gitdir_under_tmp (Apache-2.0)

## bubblewrap

- `isolation-no-nested-userns` — containers/bubblewrap tests/test-run.sh \
