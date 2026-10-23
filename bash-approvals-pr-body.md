## Summary

- Execute reviewed Bash scripts through the native owner on supported macOS OMP and Pi routes. Bind once and persistent consent to captured code, arguments, execution context and declared effects; check current restrictions at each launch.
- Preserve realistic pipelines, bounded loops and literal sourced files. Revalidate code and package metadata while keeping analysis-cache hits separate from permission. Refuse unsupported execution capabilities before offering reusable consent.
- Authenticate result delivery and acknowledge only the final SDK result. Keep output scanning, current hard restrictions and crash/retry journal semantics. Show execution capability and both supported consent durations consistently in the review UI.
- Reconstruct cached package verdicts from signed bundles and current native authority. Package observations remain assessment inputs and cannot grant local execution permission.

## Testing

- Current review fixes: `cargo test --manifest-path rust/Cargo.toml -p hol-guard-runtime --bin hol-guard-runtime bash_ -- --test-threads=1` — 127 passed. Includes authenticated SDK-call allocation, queue-resolution scope and concurrent-rejection regressions.
- The six affected proof and approval-retry/lifecycle Python modules pass 180 cases, with one skipped. The native Cloud-vector replay and all 19 Python Cloud-vector tests pass. Source formatting, lint and the native approval contract gate pass.
- Pre-integration checkpoint `6f59484aaa09`: strict Clippy and 168 exact-wheel local cases passed, including both pinned SDKs, once/persistent consent, compatible restart, package-source changes, native reply validation and Cloud-cache transport.
- Regression cases ship in `ci/gauntlet/approval_retry.json`: `approved-bash-script-once`, `approved-bash-script-persistent-restart`, `approved-bash-script-mutation`, `approved-bash-script-denial` and `approved-bash-script-concurrency`.
- `bash_reply_rejects_a_different_authenticated_invocation_for_the_current_call` and `bash_queue_resolution_uses_the_current_native_owner` cover signed local journal/store state that the command-shaped gate cannot create. New rendered cases cover both consent durations and unavailable bindings at desktop/mobile widths, keyboard cancellation and long-command overflow; their CI result remains pending.

## Notes

- Current-head artifact, rendered review UI and successful real-agent consent/retry remain pending. Earlier wheel checks qualify their checkpoint only. `requires_gauntlet`: enforcement and harness behavior changed; release qualification remains separate.
- Intermediate integrated wheel `26583fde72` passed strict Clippy, 56 packaged reply checks and six package-source SDK cases on OMP 18.11.3/Pi 0.87.1. Its general SDK matrix passed 22 of 24 cases; both failed compiled-helper cases passed isolated reruns on the same wheel. This is not a complete matrix pass.
- Follow-up CI fixes restore imports after the test split and update the historical unreachable-Cloud cache fixture to require reconstructed signed findings and unknown entitlement. The block decision is unchanged.
- The first five-case real-agent run exposed a macOS workspace-alias mismatch in native post-delivery verification. The native fix canonicalizes the project before checking the signed allocation. Its regression passes; final-wheel and real-agent reruns remain pending. Protection cases now require the same complete owner-wrapper proof as benign consent cases, without changing the core lane.
- Intermediate `a18f3f3e3d` passed all 168 exact-wheel local cases and strict Clippy. Its real-agent run passed once consent, ten executions across persistent-consent restart, and current-policy denial. Mutation and concurrency exposed a fixture restart race and an unrecorded concurrent rejection; both are addressed in the latest source. Qualification now requires a signed rejection for the actual SDK call beside the successful call in one model response. The rejected call cannot allocate execution, claim consent or acknowledge the owner's result.
- Supported execution evidence is macOS on Apple silicon with pinned OMP/Pi SDKs. Other platforms, host adapters and opaque or dynamic code retain explicit unsupported or unproven status.
- Performance targets remain unmet. On intermediate `a18f3f3e3d` under concurrent host load, warm p95 was 90 ms for two inputs and 296 ms for 64 inputs/1 MB; cold p95 was 63 ms and 556 ms respectively. Unchanged identity and same-size/same-mtime mutation controls passed. The 20 ms warm/100 ms cold budgets remain unchanged; final-source measurement remains pending. Composed Cloud execution enforcement is outside this diff. Local consent remains independent of billing.
