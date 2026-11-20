//! `codex_remote_launch` op `prepare`: the launch sequence that connects a
//! Codex TUI to a local app-server (`guarded_codex_launch_command_from_prefix`
//! and `_start_direct_app_server` before they moved here).
//!
//! The client runs each process an answer names, with its own environment
//! and the canonical Codex prefix, and sends back what happened: the exit
//! code of `remote-control start`, or the pid of a direct app-server. The
//! resident decides the next step and records the pid. The sequence ends
//! with `{"launch": "remote"}` when the control socket is ready, else
//! `{"launch": "plain"}`.

use std::path::Path;

use serde_json::{json, Map, Value};

#[cfg(unix)]
use super::codex_remote_launch::PID_FILE;
use super::codex_remote_launch::{reclaim_state, wait_ready};
use super::runner_authority_op::{KindResult, ERR_INVALID};

const KEYS: [&str; 7] = [
    "op", "home_dir", "socket", "seconds", "stage", "exit", "pid",
];
const START_TIMEOUT_SECONDS: u64 = 10;

fn launch(remote: bool) -> KindResult {
    Ok(json!({ "launch": if remote { "remote" } else { "plain" } }))
}

pub(super) fn prepare(map: &Map<String, Value>) -> KindResult {
    if !map.keys().all(|key| KEYS.contains(&key.as_str())) {
        return Err(ERR_INVALID);
    }
    let text = |key: &str| map.get(key).and_then(Value::as_str).ok_or(ERR_INVALID);
    let socket = Path::new(text("socket")?);
    let seconds = map
        .get("seconds")
        .and_then(Value::as_f64)
        .filter(|seconds| seconds.is_finite() && *seconds >= 0.0)
        .ok_or(ERR_INVALID)?;
    if !socket.is_absolute() {
        return Err(ERR_INVALID);
    }
    match text("stage")? {
        "start" => {
            let home = Path::new(text("home_dir")?);
            let codex_home = home.join(".codex");
            if std::fs::create_dir_all(&codex_home).is_err() {
                return launch(false);
            }
            Ok(json!({
                "stage": "started",
                "run": ["remote-control", "start", "--json"],
                "timeout": START_TIMEOUT_SECONDS,
                "env": { "HOME": home, "CODEX_HOME": codex_home },
            }))
        }
        "started" => {
            let exit = map.get("exit").ok_or(ERR_INVALID)?;
            if !exit.is_null() && !exit.is_i64() {
                return Err(ERR_INVALID);
            }
            if exit.as_i64() == Some(0) && wait_ready(socket, seconds) {
                return launch(true);
            }
            direct(socket, seconds)
        }
        "spawned" => {
            let pid = map
                .get("pid")
                .and_then(Value::as_u64)
                .filter(|pid| (1..=u64::from(i32::MAX.unsigned_abs())).contains(pid))
                .ok_or(ERR_INVALID)?;
            if record_pid(socket, pid).is_err() {
                return launch(false);
            }
            launch(wait_ready(socket, seconds))
        }
        _ => Err(ERR_INVALID),
    }
}

/// A direct `app-server` on the socket, where the managed daemon did not
/// come up. Windows has no Unix control socket for it.
fn direct(socket: &Path, seconds: f64) -> KindResult {
    if cfg!(windows) {
        return launch(false);
    }
    if wait_ready(socket, seconds) {
        return launch(true);
    }
    if private_directory(socket).is_err() {
        return launch(false);
    }
    match reclaim_state(&socket.to_string_lossy(), seconds) {
        "ready" => launch(true),
        "free" => Ok(json!({
            "stage": "spawned",
            "spawn": ["app-server", "--listen", format!("unix://{}", socket.display())],
        })),
        _ => launch(false),
    }
}

/// The socket's directory exists and only the user can enter it.
fn private_directory(socket: &Path) -> std::io::Result<()> {
    let parent = socket.parent().ok_or(std::io::ErrorKind::InvalidInput)?;
    std::fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Write the started server's pid beside the socket, owner-only, without
/// following a link planted at the path.
#[cfg(unix)]
fn record_pid(socket: &Path, pid: u64) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let path = socket
        .parent()
        .ok_or(std::io::ErrorKind::InvalidInput)?
        .join(PID_FILE);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::ErrorKind::InvalidInput.into());
    }
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    file.write_all(pid.to_string().as_bytes())
}

#[cfg(not(unix))]
fn record_pid(_socket: &Path, _pid: u64) -> std::io::Result<()> {
    Err(std::io::ErrorKind::Unsupported.into())
}

#[cfg(test)]
#[path = "codex_remote_prepare_tests.rs"]
mod tests;
