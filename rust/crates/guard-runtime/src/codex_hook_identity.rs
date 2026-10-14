//! The bridge's own process identity: a port of `current_process_identity`
//! in `live_process_identity.py`. The daemon uses it to tell whether the
//! hook process still waits on a browser approval, so the start token must
//! match what the Python verifier recomputes for the same PID.

/// `current_process_identity()`: this process's PID and start token.
pub(crate) fn current_process_identity() -> Option<(u32, String)> {
    let pid = std::process::id();
    process_start_token(pid).map(|token| (pid, token))
}

#[cfg(any(windows, test))]
#[path = "codex_hook_identity_windows.rs"]
mod windows_identity;
#[cfg(windows)]
pub(crate) use windows_identity::process_start_token;

#[cfg(unix)]
#[path = "codex_hook_identity_posix.rs"]
mod posix;
#[cfg(unix)]
pub(crate) use posix::process_start_token;
