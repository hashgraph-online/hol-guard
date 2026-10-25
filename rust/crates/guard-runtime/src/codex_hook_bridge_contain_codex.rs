//! Which Codex launched the hook, and whether it applies `updatedInput`:
//! `launching_codex_executable` and `codex_applies_updated_input` from
//! `codex_contained_tests.py`.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::claude_hook_bridge_render::py_strip;

const MIN_VERSION: (u128, u128, u128) = (0, 131, 0);
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

/// The same walk on Windows, over one snapshot of every process's parent.
/// Python started from its parent, the bridge's position, so this does too.
/// A parent id outlives its process and can be reused, so each parent must
/// have started no later than its child; one that started later, or whose
/// start cannot be read, ends the walk. An image that cannot be read does
/// not: the start time already proved the ancestor.
#[cfg(windows)]
pub(super) fn launching_codex_executable() -> Option<PathBuf> {
    use guard_runtime_windows_process::{process_parent_ids, running_process_image_path};

    let parents = process_parent_ids().ok()?;
    let mut child = std::process::id();
    let mut child_start = windows_start_time(child)?;
    for _ in 0..MAX_ANCESTORS {
        let pid = parents.get(&child).copied().unwrap_or(0);
        // 0 is the idle process and 4 the kernel's System process.
        if pid <= 4 {
            return None;
        }
        let start = windows_start_time(pid)?;
        if start > child_start {
            return None;
        }
        if let Ok(path) = running_process_image_path(pid) {
            if is_codex(&path) {
                return Some(path);
            }
        }
        child = pid;
        child_start = start;
    }
    None
}

/// A running process's creation time, as `windows:` and 16 hex digits.
#[cfg(windows)]
pub(super) fn windows_start_time(pid: u32) -> Option<u64> {
    let marker = guard_runtime_windows_process::running_process_start_marker(pid).ok()?;
    u64::from_str_radix(marker.strip_prefix("windows:")?, 16).ok()
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
pub(super) fn launching_codex_executable() -> Option<PathBuf> {
    None
}

#[cfg(any(target_os = "macos", target_os = "linux", windows))]
const MAX_ANCESTORS: usize = 6;

/// Release archives name the binary for its target, as
/// `codex-aarch64-apple-darwin`.
#[cfg(any(target_os = "macos", target_os = "linux", windows))]
const RELEASE_TARGETS: &[&str] = &[
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-musl",
    "x86_64-unknown-linux-musl",
    "aarch64-pc-windows-msvc",
    "x86_64-pc-windows-msvc",
];

/// `is_codex_binary_name`: `codex` or an official release binary named for
/// its target. The npm, bun and Homebrew launchers start this native binary
/// as their child, so it is always the nearer ancestor of the hook; a `node`
/// or `bun` process is never taken for Codex.
/// Windows matches the name case-insensitively and without `.exe`.
#[cfg(any(target_os = "macos", target_os = "linux", windows))]
pub(super) fn is_codex(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    #[cfg(windows)]
    let name = {
        let lower = name.to_lowercase();
        match lower.strip_suffix(".exe") {
            Some(stem) => stem.to_owned(),
            None => lower,
        }
    };
    #[cfg(windows)]
    let name = name.as_str();
    match name.split_once('-') {
        None => name == "codex",
        Some((prefix, target)) => prefix == "codex" && RELEASE_TARGETS.contains(&target),
    }
}

/// `codex_applies_updated_input(executable, deadline=deadline)`: `codex
/// --version` reports a release that applies `updatedInput` within the hook
/// deadline.
pub(super) fn codex_applies_updated_input(executable: &Path, deadline: Instant) -> bool {
    use std::io::Read;
    use std::process::{Command, Stdio};

    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return false;
    }
    let mut command = Command::new(executable);
    command.arg("--version").env_clear();
    if !probe_environment(&mut command) {
        return false;
    }
    let probe_deadline = Instant::now() + remaining.min(VERSION_PROBE_TIMEOUT);
    let Ok(mut child) = command
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

/// `_probe_environment()`: a fixed `PATH` and the user's home.
#[cfg(unix)]
fn probe_environment(command: &mut std::process::Command) -> bool {
    let Some(home) = user_home("") else {
        return false;
    };
    command
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", crate::daemon_lifecycle_text::norm_path(&home));
    true
}

/// On Windows `SYSTEMROOT`, its `System32` as `PATH`, and `USERPROFILE`
/// as `Path.home()` reads it.
#[cfg(windows)]
fn probe_environment(command: &mut std::process::Command) -> bool {
    let system_root = std::env::var_os("SYSTEMROOT").unwrap_or_else(|| r"C:\Windows".into());
    let mut path = PathBuf::from(&system_root);
    path.push("System32");
    command.env("SYSTEMROOT", &system_root).env("PATH", path);
    let Some(home) = crate::claude_hook_bridge::home_directory() else {
        return false;
    };
    command.env("USERPROFILE", home);
    true
}

#[cfg(not(any(unix, windows)))]
fn probe_environment(_command: &mut std::process::Command) -> bool {
    false
}

/// `_VERSION.match(stdout.strip())` with a release at or above 0.131.0, or
/// a pre-release whose base is above it: a pre-release sorts before its
/// base, so `0.131.0-alpha.N` can predate the rewrite support.
pub(super) fn version_supported(stdout: &str) -> bool {
    let Some(version) = py_strip(stdout).strip_prefix("codex-cli ") else {
        return false;
    };
    let (base, pre_release) = match version.split_once('-') {
        Some((base, label)) => (base, Some(label)),
        None => (version, None),
    };
    let label_valid = |label: &str| {
        !label.is_empty()
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
    };
    if pre_release.is_some_and(|label| !label_valid(label)) {
        return false;
    }
    let parts: Vec<&str> = base.split('.').collect();
    let [major, minor, patch] = parts.as_slice() else {
        return false;
    };
    let number = |part: &str| {
        (!part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| part.parse::<u128>().ok())
            .flatten()
    };
    match (number(major), number(minor), number(patch)) {
        (Some(major), Some(minor), Some(patch)) if pre_release.is_some() => {
            (major, minor, patch) > MIN_VERSION
        }
        (Some(major), Some(minor), Some(patch)) => (major, minor, patch) >= MIN_VERSION,
        _ => false,
    }
}
