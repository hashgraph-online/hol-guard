## Summary
- Score Codex hook health from live PreToolUse and PermissionRequest intercepts instead of authenticated manifest identity.
- Score Cursor hook health from live blocking hook intercepts instead of attested CLI or script identity.
- Keep stale fallback identity, extra third-party hook groups, and attested-identity drift as repair work, not machine-wide local protection failures.

## Testing
- `pytest tests/test_guard_protection_recovery.py`
