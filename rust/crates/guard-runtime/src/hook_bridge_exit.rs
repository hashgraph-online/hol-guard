//! The exit code a native hook bridge passes on from the Python bridge it
//! ran, so the harness sees what Python's own exit would have told it.

use std::process::ExitStatus;

/// The child's exit code, or `128 + signal` for a child a signal ended, as
/// a shell reports it.
#[cfg(unix)]
pub(crate) fn exit_code(status: ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1)
}

/// The child's exit code. A Windows process always has one, so the `1`
/// fallback is never expected.
#[cfg(windows)]
pub(crate) fn exit_code(status: ExitStatus) -> i32 {
    status.code().unwrap_or(1)
}
