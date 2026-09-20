# Windows private state replacement

The daemon writes a private temporary file in the destination directory, flushes
and closes it, then performs one atomic replacement. State publication retains
its existing writer lock and authenticated token/state checks. This is an
internal filesystem operation; it does not introduce a public native reason code.

On Windows, a replacement may select `FileRenameInfoEx` with replace-existing and
POSIX semantics after positive Windows RS1-or-later and exact-source-handle
filesystem capability admission. Unavailable or unsupported admission selects
the original `os.replace` operation before any mutation. An attempted native
replacement never falls back or retries.

The normal bounded and TextIO readers share deletion without gaining write or
delete access. Supported Unicode CRT defaults retain their original audited
UCRT read semantics; this legacy route does not promise improved deletion
sharing. Original descriptor, file type, size, privacy and final authority
checks remain in place. No explicit Windows owner/DACL proof is added.

## Error contract

Every selected operation retains its actual operating-system failure. Cleanup
must not replace the first exception. An audit callback can refuse the operation
before the additional native opens, and its original exception object propagates.
There is one mutation attempt, no error-code translation and no retry.

The two Windows primitives need not emit an identical raw `winerror`. In actual
Python 3.10 and 3.12 controls, a CRT-held destination that denies delete sharing
produces `PermissionError` with `errno == 13` in both arms: the original
`MoveFileExW` operation reports `winerror == 5`, while `FileRenameInfoEx` reports
`winerror == 32`. Both fail without replacing the destination and close all
owned handles. The controls retain both raw errors and require all remaining
result fields, single-attempt behavior, destination contents and cleanup to
match. Read-only and directory destination controls retain their exact native
error expectations.

The earlier comparison that required raw-code equality failed and remains
evidence; it is not reclassified as a passing run. That stronger equality was
introduced by the new comparison fixture. The existing internal writer callers
propagate or handle `OSError`; none branches on this writer's `winerror` or
`errno`. Unrelated Windows lock and keyring code has its own error classifications
and is unchanged.

## Validation and limits

The permanent Windows source lane runs the focused reader/writer modules and the
existing daemon atomic-replacement selector. Its observer forwards the actually
selected legacy or native operation and retains the same-directory, temporary
name and two-destination assertions. Installed-wheel validation remains a
separate gate.

Capability admission is not a claim of support on every Windows filesystem.
Native failures remain visible. Full-path replacement retains the original
same-directory path scope; it does not establish an all-ancestor namespace
proof. A successful controlled overlap does not attribute a historical startup
failure to a particular handle, or explain unrelated evidence-journal failures.
