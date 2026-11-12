//! `runner_authority` kind `codex_remote_launch`: whether a Codex launch can
//! connect its TUI to the local app-server, whether that server's control
//! socket is ready, and whether a tracked process is the server listening on
//! it (`_supports_remote_tui`, `_wait_for_socket`, `_socket_is_trusted`,
//! `_socket_is_live` and the tracked-command check in `_start_direct_app_server`
//! before they moved here).
//!
//! Python keeps the processes: it runs `codex remote-control start`, starts a
//! direct app-server, tracks its pid and stops a stale one. The resident runs
//! as the launching user, so its uid is the one the socket must belong to.

use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};

/// Subcommands that run without the interactive TUI, so `--remote` has
/// nothing to connect.
const REMOTE_INCOMPATIBLE_SUBCOMMANDS: [&str; 19] = [
    "app-server",
    "apply",
    "cloud",
    "completion",
    "debug",
    "doctor",
    "exec",
    "exec-server",
    "features",
    "help",
    "login",
    "logout",
    "mcp",
    "mcp-server",
    "plugin",
    "remote-control",
    "review",
    "sandbox",
    "update",
];
const INFORMATION_FLAGS: [&str; 4] = ["--help", "-h", "--version", "-V"];
/// The caller's ready budget is bounded below the per-call resident budget.
const MAX_WAIT_SECONDS: f64 = 5.0;
const POLL_INTERVAL: Duration = Duration::from_millis(50);
#[cfg(unix)]
const CONNECT_TIMEOUT: Duration = Duration::from_millis(200);

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let map = args_object(args)?;
    match map.get("op").and_then(Value::as_str) {
        Some("plan") if map.len() == 3 => plan(map),
        Some("wait") if map.len() == 3 => wait(map),
        Some("tracked") if map.len() == 3 => tracked(map),
        _ => Err(ERR_INVALID),
    }
}

fn text<'a>(map: &'a Map<String, Value>, key: &str) -> Result<&'a str, &'static str> {
    map.get(key).and_then(Value::as_str).ok_or(ERR_INVALID)
}

/// The argv tails a launch may use after the Codex executable prefix, in
/// preference order: the remote TUI first when the arguments allow it, then
/// the arguments unchanged.
fn plan(map: &Map<String, Value>) -> KindResult {
    let args = map
        .get("args")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|arg| arg.as_str().ok_or(ERR_INVALID))
        .collect::<Result<Vec<&str>, _>>()?;
    let socket = text(map, "socket")?;
    if !supports_remote_tui(&args) {
        return Ok(json!({ "tails": [args] }));
    }
    let listener = format!("unix://{socket}");
    let mut remote = vec!["--remote", listener.as_str()];
    remote.extend(&args);
    Ok(json!({ "tails": [remote, args] }))
}

/// A launch that already names a remote, only prints information, or runs a
/// non-interactive subcommand keeps its own argv.
fn supports_remote_tui(args: &[&str]) -> bool {
    !args.iter().any(|arg| {
        *arg == "--remote"
            || arg.starts_with("--remote=")
            || INFORMATION_FLAGS.contains(arg)
            || REMOTE_INCOMPATIBLE_SUBCOMMANDS.contains(arg)
    })
}

/// Whether the control socket became trusted and accepted a connection
/// within `seconds`, polling every 50 milliseconds.
fn wait(map: &Map<String, Value>) -> KindResult {
    let socket = Path::new(text(map, "socket")?);
    let seconds = map
        .get("seconds")
        .and_then(Value::as_f64)
        .filter(|seconds| seconds.is_finite() && *seconds >= 0.0)
        .ok_or(ERR_INVALID)?;
    if !socket.is_absolute() {
        return Err(ERR_INVALID);
    }
    let deadline = Instant::now() + Duration::from_secs_f64(seconds.min(MAX_WAIT_SECONDS));
    while Instant::now() < deadline {
        if ready(socket) {
            return Ok(json!({ "ready": true }));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    Ok(json!({ "ready": false }))
}

/// Whether a tracked process command line is the app-server listening on this
/// socket, so a stale one can be reused or stopped instead of a stranger.
fn tracked(map: &Map<String, Value>) -> KindResult {
    let command = text(map, "command")?;
    let listener = format!("unix://{}", text(map, "socket")?);
    Ok(json!({ "ours": launched_listener(command, &listener) }))
}

/// Whether `command` holds the argument run Guard launches,
/// `app-server --listen unix://<socket>`, as whole adjacent arguments. The
/// socket path itself names `app-server`, so a stray mention never counts.
fn launched_listener(command: &str, listener: &str) -> bool {
    fn after_space(text: &str) -> Option<&str> {
        let rest = text.trim_start();
        (rest.len() < text.len()).then_some(rest)
    }
    command.match_indices("app-server").any(|(start, word)| {
        if !command[..start].ends_with(char::is_whitespace) {
            return false;
        }
        after_space(&command[start + word.len()..])
            .and_then(|rest| rest.strip_prefix("--listen"))
            .and_then(after_space)
            .and_then(|rest| rest.strip_prefix(listener))
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(char::is_whitespace))
    })
}

/// `_socket_is_trusted` and `_socket_is_live`: a socket the user owns, in a
/// directory the user owns that no one else can write, that accepts a
/// connection.
#[cfg(unix)]
fn ready(socket: &Path) -> bool {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let parent = socket.parent().unwrap_or(Path::new("/"));
    let (Ok(metadata), Ok(directory)) = (std::fs::metadata(socket), std::fs::metadata(parent))
    else {
        return false;
    };
    let uid = nix::unistd::getuid().as_raw();
    let trusted = metadata.file_type().is_socket()
        && metadata.uid() == uid
        && directory.uid() == uid
        && directory.mode() & 0o022 == 0;
    trusted
        && crate::codex_app_server_socket::connect(socket, Instant::now() + CONNECT_TIMEOUT).is_ok()
}

#[cfg(not(unix))]
fn ready(_socket: &Path) -> bool {
    false
}

#[cfg(test)]
#[path = "codex_remote_launch_tests.rs"]
mod tests;
