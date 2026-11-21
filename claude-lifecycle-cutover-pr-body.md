## Summary

- Route Claude permission, notification, and stop lifecycle events through the Rust hook edge.
- Retire the Python lifecycle response branch and its duplicate authority-state rendering.
- Move Claude `PostToolUse` approval-question settlement into the Rust resident, including the policy-integrity generation lock, signed policy write, finalization, and pending-row consume.
- Remove the retired Python question-settlement modules and keep only a compatibility transport for legacy imports.
- Replace the Python lifecycle tests with native-edge routing coverage.

## Testing

- `uv run --frozen pytest -q tests/test_claude_permission_request.py tests/test_native_hook_direct.py tests/test_daemon_cli_helper_registry.py`
- `HOL_GUARD_NATIVE=force HOL_GUARD_NATIVE_BINARY=<built runtime> uv run --frozen pytest -q tests/test_guard_runtime.py -k 'claude_ask_user_question or signed_unseen_pending or unsigned_legacy_pending or unsigned_bound_pending'`
- `rustup run 1.89.0 cargo test --locked --manifest-path rust/Cargo.toml -p hol-guard-runtime lifecycle --lib` (215 passed)
- `uv run --frozen basedpyright --level error src/codex_plugin_scanner/guard/hook_review/hook_worker.py`
- `ruff check ...`
- `git diff --check`

This change is in scope for release qualification because it changes native hook authority routing.
