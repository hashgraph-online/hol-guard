# Troubleshooting Fast Hook Review

## Daemon Not Using Fast Path

**Symptom**: Hook decisions still go through the legacy CLI path.

**Check**:
1. Verify `HOL_GUARD_HOOK_FAST_PATH=1` is set in the daemon's environment.
2. Check that the daemon is running: `hol-guard status`.
3. Look for `reason_code: "daemon_worker_exception"` in responses — this indicates the worker crashed and returned a fail-safe deny.

**Resolution**: The fast path is behind a feature flag. Set `HOL_GUARD_HOOK_FAST_PATH=1` and restart the daemon.

## Source Reads Still Return Excerpts

**Symptom**: Safe source-file reads still get `replace_with_reviewed_excerpt` instead of `allow_original`.

**Check**:
1. Verify the Pi extension is generating `guard_source_ref` (check `HOL_GUARD_HOOK_SOURCE_REF=1`).
2. Check the `reason_code` in the response:
   - `output_mismatch`: The adapter's hash doesn't match the file content
   - `sensitive_path`: The file is `.env`, `.npmrc`, etc.
   - `symlink_in_path`: A path component is a symlink
   - `binary_file`: The file contains null bytes
   - `invalid_utf8`: The file is not valid UTF-8
   - `source_file_too_large`: Exceeds 5MB
   - `scanner_budget_exhausted`: Scanner deadline expired
   - `source_stat_changed`: TOCTOU detection (file changed during read)

**Resolution**: Fix the underlying issue. For `output_mismatch`, ensure the extension hashes the exact same text the model sees. For `scanner_budget_exhausted`, the file may be too large or the system too slow.

## Cache Not Hitting

**Symptom**: Source reads that were previously fast are now slow (no `source_cache_hit`).

**Check**:
1. The file content changed (different `content_sha256`).
2. The file stat changed (different `stat_mtime_ns` or `stat_size`).
3. The policy changed (different `policy_fingerprint`).
4. The config changed (different `config_fingerprint`).
5. The scanner rules changed (different `scanner_version`).

**Resolution**: Cache misses are expected when any of these change. The next read will re-scan and cache the result.

## Daemon Worker Exception

**Symptom**: Response has `reason_code: "daemon_worker_exception"`.

**Check**: The worker encountered an unexpected exception. This is a fail-safe deny/block — no raw output reaches the model.

**Resolution**: Check the daemon logs. The legacy CLI path is not used as a fallback for worker exceptions on source-ref requests (to avoid passing unreviewed output through).

## CLI Fallback Not Understanding Source Refs

**Symptom**: CLI fallback returns an error or doesn't handle `guard_source_ref`.

**Check**: Ensure you're running a recent version of HOL Guard whose CLI routes command PreToolUse and PostToolUse through native hook authority. Python source-ref review remains for off/shadow rollback, and for file PreToolUse the native worker cannot handle. In that unsupported-file case the worker reports the event as unsupported, then the CLI uses the existing source-ref path. That path is not a native-runtime failure.

**Resolution**: Update HOL Guard: `hol-guard update`.

## App Hooks Fail While Shell Review Fail-Closes

**Symptom**: Local protection repair reports App hooks failed, and Cursor or other app shells return `HOL Guard could not complete the native PreToolUse decision safely`.

**Check**:
1. Desktop-managed Core sidecars must include `hol-guard-runtime` next to `runtime-manifest.json` inside the signed Core executable.
2. `reason_code: "native_pre_tool_unavailable"` or `reason_code: "native_post_tool_unavailable"` means the daemon could not complete native command review. Auto/force still fail closed; they do not fall back to the Python engine.
3. Stale app hook scripts are missing `HOL_GUARD_NATIVE` inherit keys or still pin an older CLI identity.

**Resolution**: Update HOL Guard so Desktop Core is rebuilt from the attested platform wheel, then re-run `hol-guard install cursor` (or the matching harness install) and retry repair. The attested CLI retries only when the daemon reports native unavailability, and that CLI path still requires the bundled runtime.
