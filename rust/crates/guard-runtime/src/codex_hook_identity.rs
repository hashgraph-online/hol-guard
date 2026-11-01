//! The bridge's own process identity: a port of `current_process_identity`
//! in `live_process_identity.py`. The daemon uses it to tell whether the
//! hook process still waits on a browser approval, so the start token must
//! match what the Python verifier recomputes for the same PID.

#[cfg(test)]
#[path = "codex_hook_identity_tests.rs"]
mod tests;

/// `current_process_identity()`: this process's PID and start token.
pub(crate) fn current_process_identity() -> Option<(u32, String)> {
    let pid = std::process::id();
    process_start_token(pid).map(|token| (pid, token))
}

/// `process_identity_matches(value)`: the captured `{pid, startToken}` still
/// names the same live process. Any other shape is not proof.
pub(crate) fn process_identity_matches(value: &serde_json::Value) -> bool {
    let Some(identity) = value.as_object() else {
        return false;
    };
    if identity.len() != 2 {
        return false;
    }
    let pid = identity
        .get("pid")
        .and_then(serde_json::Value::as_u64)
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid > 0);
    let token = identity
        .get("startToken")
        .and_then(serde_json::Value::as_str)
        .filter(|token| !token.is_empty());
    match (pid, token) {
        (Some(pid), Some(token)) => process_start_token(pid).as_deref() == Some(token),
        _ => false,
    }
}

#[cfg(any(windows, test))]
#[path = "codex_hook_identity_windows.rs"]
mod windows_identity;
#[cfg(windows)]
pub(crate) use windows_identity::{
    process_owner_marker, process_start_token, process_start_token_within,
};

#[cfg(unix)]
#[path = "codex_hook_identity_posix.rs"]
mod posix;
#[cfg(unix)]
pub(crate) use posix::{process_owner_marker, process_start_token, process_start_token_within};
