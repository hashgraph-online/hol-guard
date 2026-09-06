## Summary
- Share one trailing-operand base matcher (field normalization plus the candidate segment scan) across the prefix, host-target, and remote-alias matchers
- Route the three device-key lease signing verbs through one payload-signing helper that keeps the existing validation order
- Extract the DPoP request builder and nonce-retry token POST shared by the device-code, authorization-code, and refresh-token exchanges
- Route the three cloud exception sync calls (submit command-policy, submit exception, fetch) through one request helper carrying the shared auth resolution, retry, and error mapping

## Testing
- `pytest tests/test_guard_command_blitcp_extensions.py tests/test_cloud_exception_requests.py tests/test_guard_connect_flow.py tests/test_guard_mdm_device_key.py tests/test_guard_mdm_device_key_signing.py tests/test_guard_mdm_health_key_registration.py tests/test_guard_exact_cloud_review_oauth.py` — 95 passed, 5 skipped
- New request-path tests for the cloud exception sync helper (success POST with normalized payload + bearer auth, GET with explicit auth context, HTTP 409/500 → 409/502 mapping, transport error → 502, non-dict response → 502, not-configured and expired authorization → 401): `tests/test_cloud_exception_requests.py` — 23 passed, and the consolidated `_guard_cloud_exception_sync_request` lines report fully covered under `coverage run`
- `pytest tests/test_guard_command_decision_diff.py` — 6 passed after refreshing the source-bound fixture via the corpus runner
- `basedpyright --level error` on all four changed sources and the test file — 0 errors
- `ruff check` / `ruff format --check`, `scripts/ci/test_inventory.py`, `scripts/ci/code_quality_audit.py` — all pass

## Notes
- Matcher constructions are keyword-compatible with the previous field sets; only the ValueError wording for whitespace-only executables differs, and no test asserts those strings
- The mirrored secret-like source detection in commands_support_codex_commands.py and commands_support_codex_tool_output.py was left untouched deliberately: the two review paths keep mirrored constants by design and deserve their own careful pass
