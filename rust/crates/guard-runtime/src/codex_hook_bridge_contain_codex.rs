//! Which Codex launched the hook, and whether it applies `updatedInput`:
//! `launching_codex_executable` and `codex_applies_updated_input` from
//! `codex_contained_tests.py`.

use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::time::Duration;
use std::time::Instant;

#[cfg(unix)]
use crate::claude_hook_bridge_render::py_strip;

#[cfg(unix)]
const MIN_VERSION: (u128, u128, u128) = (0, 131, 0);
#[cfg(unix)]
const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// `os.path.expanduser("~user")` for the current user (`user` empty) or a
/// named one; `None` where Python would leave the `~` in place.
#[cfg(unix)]
pub(super) fn user_home(user: &str) -> Option<String> {
    let home = if user.is_empty() {
        match std::env::var("HOME") {
            Ok(home) => home,
            Err(std::env::VarError::NotPresent) => {
                nix::unistd::User::from_uid(nix::unistd::getuid())
                    .ok()??
                    .dir
                    .to_str()?
                    .to_owned()
            }
            Err(std::env::VarError::NotUnicode(_)) => return None,
        }
    } else {
        nix::unistd::User::from_name(user)
            .ok()??
            .dir
            .to_str()?
            .to_owned()
    };
    let trimmed = home.trim_end_matches('/');
    Some(if trimmed.is_empty() { "/" } else { trimmed }.to_owned())
}

/// `launching_codex_executable()`: the nearest `codex` among this process
/// and its ancestors. Python starts from its parent, which is this bridge.
#[cfg(target_os = "macos")]
pub(super) fn launching_codex_executable() -> Option<PathBuf> {
    let mut pid = i64::from(std::process::id());
    for _ in 0..MAX_ANCESTORS {
        if pid <= 1 {
            return None;
        }
        let process = i32::try_from(pid).ok()?;
        let path = PathBuf::from(libproc::proc_pid::pidpath(process).ok()?);
        if is_codex(&path) {
            return Some(path);
        }
        let info = libproc::proc_pid::pidinfo::<libproc::bsd_info::BSDInfo>(process, 0).ok()?;
        pid = i64::from(info.pbi_ppid);
    }
    None
}

/// The same walk through `/proc`: each process's executable and parent.
#[cfg(target_os = "linux")]
pub(super) fn launching_codex_executable() -> Option<PathBuf> {
    let mut pid = i64::from(std::process::id());
    for _ in 0..MAX_ANCESTORS {
        if pid <= 1 {
            return None;
        }
        let path = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
        if is_codex(&path) {
            return Some(path);
        }
        let stat = std::fs::read(format!("/proc/{pid}/stat")).ok()?;
        let stat = String::from_utf8_lossy(&stat);
        // The command name can hold spaces and parentheses; the fields
        // after its closing one are fixed.
        let tail = stat
            .rsplit_once(')')
            .map_or(stat.as_ref(), |(_, tail)| tail);
        pid = tail.split_whitespace().nth(1)?.parse().ok()?;
    }
    None
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(super) fn launching_codex_executable() -> Option<PathBuf> {
    None
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
const MAX_ANCESTORS: usize = 6;

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn is_codex(path: &Path) -> bool {
    path.file_name().is_some_and(|name| name == "codex")
}

/// `codex_applies_updated_input(executable, deadline=deadline)`: `codex
/// --version` reports a stable release at or above 0.131.0 within the
/// hook deadline.
#[cfg(unix)]
pub(super) fn codex_applies_updated_input(executable: &Path, deadline: Instant) -> bool {
    use std::io::Read;
    use std::process::{Command, Stdio};

    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return false;
    }
    let Some(home) = user_home("") else {
        return false;
    };
    let probe_deadline = Instant::now() + remaining.min(VERSION_PROBE_TIMEOUT);
    let Ok(mut child) = Command::new(executable)
        .arg("--version")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", crate::daemon_lifecycle_text::norm_path(&home))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return false;
    };
    // A descendant can keep the pipe open after `codex` exits; the read is
    // bounded by the same deadline and the reader is left behind.
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout.take(64 * 1024).read_to_end(&mut bytes);
        let _ = sender.send(bytes);
    });
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < probe_deadline => {
                std::thread::sleep(Duration::from_millis(5));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    };
    let wait = probe_deadline.saturating_duration_since(Instant::now());
    let Ok(bytes) = receiver.recv_timeout(wait) else {
        return false;
    };
    status.code() == Some(0)
        && String::from_utf8(bytes).is_ok_and(|stdout| version_supported(&stdout))
}

#[cfg(not(unix))]
pub(super) fn codex_applies_updated_input(_executable: &Path, _deadline: Instant) -> bool {
    false
}

/// `_VERSION.match(stdout.strip())` with no pre-release and a version at or
/// above 0.131.0. Any pre-release can predate the rewrite support.
#[cfg(unix)]
pub(super) fn version_supported(stdout: &str) -> bool {
    let Some(version) = py_strip(stdout).strip_prefix("codex-cli ") else {
        return false;
    };
    let parts: Vec<&str> = version.split('.').collect();
    let [major, minor, patch] = parts.as_slice() else {
        return false;
    };
    let number = |part: &str| {
        (!part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| part.parse::<u128>().ok())
            .flatten()
    };
    match (number(major), number(minor), number(patch)) {
        (Some(major), Some(minor), Some(patch)) => (major, minor, patch) >= MIN_VERSION,
        _ => false,
    }
}
