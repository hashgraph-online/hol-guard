## Summary
- Keep daemon `allow` answers for Oh My Pi and Pi PostToolUse instead of discarding them when output-hash proof is missing.
- Preserve non-truncated tool results after a daemon allow; still block mismatched `allow_original` hashes.
- Timeout copy no longer tells the model to wait for a human approval that does not exist.

## Testing
- `uv run pytest tests/test_pi_extension_response_contract.py tests/test_pi_adapter.py tests/test_pi_extension_runtime_ownership.py tests/test_guard_observe_mode_liveness.py tests/test_guard_install_workspace.py`
