# Gauntlet Rust migration development

The cumulative migration branch is `codex/gauntlet-rust-integration-20261020`
in `HGraphPunks/hol-guard`. Upstream draft PR
https://github.com/hashgraph-online/hol-guard/pull/5402 targets `main` and
remains draft while migration exits are open.

Use this development cycle for each consolidated chunk:

1. Inspect and commit any existing work before changing branches. Use focused
   Conventional Commit messages and record incomplete validation explicitly.
2. Fetch the integration branch and `hashgraph-online/hol-guard` `main`.
   Create a new `codex/gauntlet-rust-<scope>-<date>` branch from the current
   integration head. Merge current upstream `main` into that child branch
   when it is ahead; preserve published history.
3. Resolve conflicts by preserving both upstream behavior and migration
   behavior. Refresh `integration-source-delta.v1.json` for reviewed Gauntlet
   source changes with `proofs/refresh_integration_source_delta.py`. Preserve
   the immutable Python baseline and old evidence instead of regenerating
   them to hide incompatibility.
4. Complete one coherent implementation, its meaningful tests and evidence,
   and its checklist updates on the child branch. Record exact source and
   upstream pins and the limits of any live evidence.
5. Push the child branch and open a PR in `HGraphPunks/hol-guard` targeting
   the integration branch. Run the Gauntlet Rust workflow on that PR before
   merging. It covers x86 Linux contracts/Clippy, macOS host/bridge, ARM64
   executables/tests and the merged Native library/CLI compilation.
6. Inspect actual check results for the current PR head, resolve failures,
   and handle review findings. Check for relevant upstream changes again
   before merging. Do not bypass checks with admin overrides or weaken tests
   to obtain a passing result.
7. Merge the child PR into the integration branch using a merge commit,
   preserving the chunk and any upstream merge. Fetch the merged integration
   head, verify the working tree is clean, and start the next child branch.

The user has authorized creating and merging these incremental PRs into the
integration branch. This does not authorize merging PR #5402 into upstream
`main`, changing branch protections, enabling the benchmark PR gate, or
resetting retained model quota. The release observer and gate remain passive
until their explicit migration and rollout requirements are satisfied.
