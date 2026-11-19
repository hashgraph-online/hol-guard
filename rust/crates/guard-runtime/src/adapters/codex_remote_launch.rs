//! `runner_authority` kind `codex_remote_launch`: whether a Codex launch can
//! connect its TUI to the local app-server, whether that server's control
//! socket is ready, and what to do with the app-server Guard started there
//! before (`_supports_remote_tui`, `_wait_for_socket`, `_socket_is_trusted`,
//! `_socket_is_live` and the tracked-process handling in
//! `_start_direct_app_server` before they moved here).
//!
//! `prepare` (in `codex_remote_prepare`) decides the launch sequence and `run`
//! (in `codex_remote_run`) starts the processes it names. The resident reads the pid back,
//! checks the process is the server listening on the socket and stops a stale
//! one. The resident runs as the launching user, so its uid is the one the
//! socket must belong to and the one allowed to signal the server.

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
/// Written beside the socket when a direct app-server starts.
pub(super) const PID_FILE: &str = "hol-guard-app-server.pid";
const MAX_PID_FILE_BYTES: u64 = 64;
#[cfg(unix)]
const STOP_TIMEOUT: Duration = Duration::from_secs(1);
#[cfg(unix)]
const COMMAND_TIMEOUT: Duration = Duration::from_secs(1);
#[cfg(target_os = "linux")]
const MAX_COMMAND_BYTES: u64 = 1024 * 1024;

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let map = args_object(args)?;
    match map.get("op").and_then(Value::as_str) {
        Some("plan") if map.len() == 3 => plan(map),
        Some("launch") if map.len() == 4 => launch(map),
        Some("wait") if map.len() == 3 => wait(map),
        Some("reclaim") if map.len() == 3 => reclaim(map),
        Some("prepare") => super::codex_remote_prepare::prepare(map),
        Some("run") => super::codex_remote_run::run(map),
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
    let args = string_list(map.get("args"))?;
    let socket = text(map, "socket")?;
    Ok(json!({ "tails": tails(&args, socket) }))
}

pub(super) fn string_list(value: Option<&Value>) -> Result<Vec<&str>, &'static str> {
    value
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|item| item.as_str().ok_or(ERR_INVALID))
        .collect()
}

fn tails(args: &[&str], socket: &str) -> Vec<Vec<String>> {
    let plain: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
    if !supports_remote_tui(args) {
        return vec![plain];
    }
    let mut remote = vec!["--remote".to_owned(), format!("unix://{socket}")];
    remote.extend(plain.iter().cloned());
    vec![remote, plain]
}

const PREFIX_REFUSAL: &str = "Codex launch preparation requires a canonical executable prefix.";
const SHARED_REFUSAL: &str =
    "Codex launch candidates do not share one authorized executable prefix.";

/// A home's Codex home: `<home>/.codex`.
fn codex_home(home: &str) -> std::path::PathBuf {
    Path::new(home)
        .components()
        .collect::<std::path::PathBuf>()
        .join(".codex")
}

/// `default_codex_control_socket`.
fn control_socket(home: &str) -> String {
    codex_home(home)
        .join("app-server-control")
        .join("app-server-control.sock")
        .to_string_lossy()
        .into_owned()
}

/// Everything a launch needs before any process starts: the one authorized
/// executable prefix (a refusal when the candidates do not share exactly one,
/// or it is not canonical), the control socket under `home_dir`, the Codex
/// home the launch runs with, the ordinary command, the remote command when
/// the arguments allow the remote TUI, whether the client should run
/// `prepare` at all (it should exactly when there is a remote command), and
/// every command preparation may select, remote first.
pub(super) fn launch(map: &Map<String, Value>) -> KindResult {
    let mut chosen: Vec<Vec<&str>> = Vec::new();
    for prefix in map
        .get("prefixes")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?
    {
        let parts = string_list(Some(prefix))?;
        if !parts.is_empty() && !chosen.contains(&parts) {
            chosen.push(parts);
        }
    }
    let refusal = |message: &str| -> KindResult { Ok(json!({ "refusal": message })) };
    let [prefix] = chosen.as_slice() else {
        return refusal(SHARED_REFUSAL);
    };
    if prefix.iter().any(|part| part.is_empty()) {
        return refusal(PREFIX_REFUSAL);
    }
    let args = string_list(map.get("args"))?;
    let home = text(map, "home_dir")?;
    let socket = control_socket(home);
    let candidates: Vec<Vec<String>> = tails(&args, &socket)
        .into_iter()
        .map(|tail| {
            prefix
                .iter()
                .map(|part| (*part).to_owned())
                .chain(tail)
                .collect()
        })
        .collect();
    let remote = (candidates.len() >= 2).then(|| candidates[0].clone());
    Ok(json!({
        "prepare": remote.is_some(),
        "socket": socket,
        "prefix": prefix,
        "env": { "CODEX_HOME": codex_home(home).to_string_lossy() },
        "plain": candidates.last(),
        "remote": remote,
        "candidates": candidates,
    }))
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

/// The absolute control socket and ready budget a `wait` or `reclaim`
/// request names.
fn socket_and_seconds(map: &Map<String, Value>) -> Result<(&str, f64), &'static str> {
    let socket = text(map, "socket")?;
    let seconds = map
        .get("seconds")
        .and_then(Value::as_f64)
        .filter(|seconds| seconds.is_finite() && *seconds >= 0.0)
        .ok_or(ERR_INVALID)?;
    if !Path::new(socket).is_absolute() {
        return Err(ERR_INVALID);
    }
    Ok((socket, seconds))
}

/// Whether the control socket became trusted and accepted a connection
/// within `seconds`.
fn wait(map: &Map<String, Value>) -> KindResult {
    let (socket, seconds) = socket_and_seconds(map)?;
    Ok(json!({ "ready": wait_ready(Path::new(socket), seconds) }))
}

/// Polls every 50 milliseconds, for at most five seconds.
pub(super) fn wait_ready(socket: &Path, seconds: f64) -> bool {
    let deadline = Instant::now() + Duration::from_secs_f64(seconds.min(MAX_WAIT_SECONDS));
    while Instant::now() < deadline {
        if ready(socket) {
            return true;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    false
}

/// What the app-server Guard last started on this socket leaves for a new
/// one: `ready` when it is listening within `seconds`, `free` when there is
/// none, it is gone or stopped, or the pid now belongs to another process,
/// and `busy` when it cannot be identified or stopped, so it must not be
/// replaced.
fn reclaim(map: &Map<String, Value>) -> KindResult {
    let (socket, seconds) = socket_and_seconds(map)?;
    Ok(json!({ "state": reclaim_state(socket, seconds) }))
}

#[cfg(unix)]
pub(super) fn reclaim_state(socket: &str, seconds: f64) -> &'static str {
    use nix::errno::Errno;
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;

    let Some(pid) = tracked_pid(Path::new(socket)).map(Pid::from_raw) else {
        return "free";
    };
    if matches!(kill(pid, None), Err(error) if error != Errno::EPERM) {
        return "free";
    }
    let Some(command) = command_line(pid.as_raw()) else {
        return "busy";
    };
    if !launched_listener(&command, &format!("unix://{socket}")) {
        return "free";
    }
    if wait_ready(Path::new(socket), seconds) {
        return "ready";
    }
    match kill(pid, Signal::SIGTERM) {
        Ok(()) => {}
        Err(Errno::ESRCH) => return "free",
        Err(_) => return "busy",
    }
    let deadline = Instant::now() + STOP_TIMEOUT;
    while Instant::now() < deadline {
        match kill(pid, None) {
            Ok(()) => std::thread::sleep(POLL_INTERVAL),
            Err(Errno::ESRCH) => return "free",
            Err(_) => return "busy",
        }
    }
    "busy"
}

#[cfg(not(unix))]
pub(super) fn reclaim_state(_socket: &str, _seconds: f64) -> &'static str {
    let _ = (PID_FILE, MAX_PID_FILE_BYTES);
    "busy"
}

/// The positive decimal pid in the pid file beside `socket`, read without
/// following a link or waiting on a pipe.
#[cfg(unix)]
fn tracked_pid(socket: &Path) -> Option<i32> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;

    let path = socket.parent()?.join(PID_FILE);
    let file = std::fs::OpenOptions::new()
        .read(true)
        // A FIFO planted at the path would otherwise hold this worker open.
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut raw = Vec::new();
    file.take(MAX_PID_FILE_BYTES + 1)
        .read_to_end(&mut raw)
        .ok()?;
    if raw.len() as u64 > MAX_PID_FILE_BYTES {
        return None;
    }
    let text = String::from_utf8(raw).ok()?;
    let digits = crate::cloud_request_text::py_strip(&text);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse::<i32>().ok().filter(|pid| *pid > 0)
}

/// The tracked process's arguments: procfs where there is one, else the
/// trusted `ps`.
#[cfg(unix)]
fn command_line(pid: i32) -> Option<String> {
    #[cfg(target_os = "linux")]
    if let Some(command) = proc_command_line(pid) {
        return Some(command);
    }
    crate::posix_processes::command_line(i64::from(pid), COMMAND_TIMEOUT)
}

#[cfg(target_os = "linux")]
fn proc_command_line(pid: i32) -> Option<String> {
    use std::io::Read;

    let mut raw = Vec::new();
    std::fs::File::open(format!("/proc/{pid}/cmdline"))
        .ok()?
        .take(MAX_COMMAND_BYTES)
        .read_to_end(&mut raw)
        .ok()?;
    let text = String::from_utf8_lossy(&raw).replace('\0', "\n");
    let command = crate::cloud_request_text::py_strip(&text);
    (!command.is_empty()).then(|| command.to_owned())
}

/// Whether `command` holds the argument run Guard launches,
/// `app-server --listen unix://<socket>`, as whole adjacent arguments. The
/// socket path itself names `app-server`, so a stray mention never counts.
#[cfg_attr(not(unix), allow(dead_code))]
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
