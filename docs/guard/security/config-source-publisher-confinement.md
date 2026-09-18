# Native publisher config source confinement

The implementation publisher previously captured config bytes through its own
pathname reader and supplied them directly to `load_guard_config`. Fixing only
ordinary TOML loading would leave that second route unchanged. Guard TOML capture
now uses the same [bounded, held-source reader](config-source-confinement.md),
including the fixed basename check, complete byte identity, 1 MiB ceiling and
explicit rejection of unsafe or inaccessible sources. The publisher hashes and
parses those same captured bytes. Generic non-config managed-cache observation
retains its separate existing behavior.

A rejection also immediately clears `_acked` under the publisher condition lock
and notifies waiters before re-raising. This happens at the first home capture and
at both workspace captures, before any cache-entry comparison. The existing
generic publication error handler can retain an earlier unexpired acknowledgement
for a transient publication error; it must not retain one after a config-source
rejection. The ordinary observer does not need to run first for this rejection to
withdraw readiness. No new client push or weaker default policy is produced.

Nine regression cases start the actual publisher publication path with injected
test status and transport callbacks, obtain a valid acknowledgement, then make
the home, current workspace, or legacy workspace config linked, oversized, or
unreadable. A direct publication attempt must withdraw readiness and current
snapshot binding without another transport call. This is a publisher unit-test
boundary, not evidence of an installed native resident or a platform qualification
run. A separate boundary case checks that ordinary loading and capture both accept
exactly 1,048,576 bytes and reject the next byte.

The foundation-compatible reader commit was separately applied without conflicts
to `e449594e86c717e66e14598a4130475de79c536f`. Its 67 tests passed, with one actual
Windows-only test skipped, at source
`29088826f251f60d9a40f3a2fb48f9853f9b53fb`; the source and log hashes are in
[config-source-foundation-validation.json](config-source-foundation-validation.json).
The publisher change belongs only to the implementation PR. The frozen benchmark
baseline, configured performance thresholds and CodeQL query configuration remain
unchanged.

[Combined validation](config-source-publisher-validation.json) passed **88 tests**
with one Windows-only skip in 6.64 seconds. Ruff and format passed for all five
changed Python files. The three production files reported zero type errors and 80
nonfatal warnings. These counts include the earlier shared-reader suite. The
receipt retains the earlier assertion-casing error and the separate disk-full
attempt; storage was recovered before repeating the suite at the original `/tmp`
test location. The complete disk-full log is retained, while the earlier truncated
tool output is explicitly represented as a partial observation.
