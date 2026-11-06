## Summary

- Emit a short HOL Guard stderr line during Claude `PermissionRequest` hooks (non-`--json`) so terminal users see branding while approvals are reviewed.
- Set Claude hook `statusMessage` on `PreToolUse` and `PermissionRequest` installs so Claude shows HOL Guard progress during hook execution.

## Test plan

- [x] `pytest tests/test_guard_runtime.py -k "claude_permission_request" -q`
- [x] `pytest tests/test_guard_claude_adapter.py::test_claude_install_writes_session_start_and_command_hook_schema_and_is_idempotent -q`
