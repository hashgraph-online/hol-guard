//! Codex thread continuation: tells the Codex thread which queued an approval
//! how it was resolved, for a `codex_request_resume` retry.
//!
//! The caller passes the stored Codex operation metadata. This picks
//! the thread, turn, socket and command fields, refuses unsafe thread ids and
//! sockets outside the caller's home or temporary directories, and sends the
//! continuation prompt over the Codex app-server WebSocket. With a known turn
//! it first steers that turn and falls back to starting a new one.

use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use guard_command::command_option_parsing::python_is_alphanumeric;
use serde_json::{json, Map, Value};

use crate::cloud_request_text::first_optional_string;
use crate::codex_app_server_socket::{exchange, Failure};

const THREAD_ID_KEYS: [&str; 5] = [
    "codex_thread_id",
    "thread_id",
    "threadId",
    "session_id",
    "sessionId",
];
const TURN_ID_KEYS: [&str; 3] = ["codex_turn_id", "turn_id", "turnId"];
const SOCKET_KEYS: [&str; 3] = [
    "codex_app_server_socket",
    "app_server_socket",
    "appServerSocket",
];
const CODEX_HOME_KEYS: [&str; 2] = ["codex_home", "codexHome"];
const COMMAND_TEXT_KEYS: [&str; 2] = ["command_text", "commandText"];
const STRATEGY_THREAD: &str = "codex-app-server-thread";
const STRATEGY_TURN: &str = "codex-app-server-turn";
const STRATEGY_STEER: &str = "codex-app-server-steer";
const SOCKET_UNAVAILABLE_MESSAGE: &str = "Codex App remote-control socket is unavailable. HOL Guard will not start `codex exec resume` because that creates a separate background run instead of continuing the visible Codex chat.";
const REJECTED_MESSAGE: &str = "Codex app-server rejected the continuation.";
/// What one continuation needs besides the stored operation metadata.
pub(crate) struct ContinueRequest<'a> {
    /// The approval request whose resolution is being reported to Codex.
    pub(crate) approval_request_id: &'a str,
    /// `allow`, or any other resolution, which is reported as a block.
    pub(crate) action: &'a str,
    /// The caller's home directory: expands `~` and bounds trusted sockets.
    pub(crate) home_dir: Option<&'a str>,
    /// The caller's temporary directory, also a trusted socket location.
    pub(crate) temp_dir: Option<&'a str>,
    /// The caller's working directory, for a relative socket path.
    pub(crate) cwd: Option<&'a str>,
    /// How long to wait for Codex to accept the continuation.
    pub(crate) timeout_ms: u64,
}

/// `resume_codex_thread_for_request` after the operation lookup.
pub(crate) fn continue_thread(
    request: &ContinueRequest<'_>,
    metadata: &Map<String, Value>,
) -> Value {
    let deadline = Instant::now() + Duration::from_millis(request.timeout_ms);
    let Some(thread_id) = first_optional_string(metadata, &THREAD_ID_KEYS) else {
        return Value::Null;
    };
    if !is_safe_thread_id(thread_id) {
        return json!({
            "status": "skipped",
            "reason": "unsafe_thread_id",
            "thread_id": thread_id,
            "strategy": STRATEGY_THREAD,
            "supported": false,
        });
    }
    let roots = SocketRoots::new(request);
    let socket = match first_optional_string(metadata, &SOCKET_KEYS) {
        Some(text) => roots.absolute(text),
        None => roots.default_socket(first_optional_string(metadata, &CODEX_HOME_KEYS)),
    };
    let Some(socket) = socket.filter(|path| roots.is_safe(path)) else {
        return json!({
            "status": "skipped",
            "reason": "unsafe_socket_path",
            "thread_id": thread_id,
        });
    };
    if std::fs::metadata(&socket).is_err() {
        return json!({
            "status": "failed",
            "reason": "socket_not_available",
            "thread_id": thread_id,
            "strategy": STRATEGY_THREAD,
            "supported": true,
            "message": SOCKET_UNAVAILABLE_MESSAGE,
        });
    }
    let command_text = first_optional_string(metadata, &COMMAND_TEXT_KEYS);
    let prompt = continuation_prompt(request.action, request.approval_request_id, command_text);
    let resolution = if request.action == "allow" {
        "allow"
    } else {
        "block"
    };
    let client_metadata = json!({
        "hol_guard_request_id": request.approval_request_id,
        "hol_guard_resolution": resolution,
    });
    let input = json!([{ "type": "text", "text": prompt }]);
    let trusted = |path: &Path| roots.is_safe(path) && is_trusted_socket(path);
    // A turn/start that runs out of time on its own reports the socket
    // timeout; after a steer attempt the whole continuation has run out.
    let mut timeout_reason = "TimeoutError";
    if let Some(turn_id) = first_optional_string(metadata, &TURN_ID_KEYS) {
        timeout_reason = "turn_start_timeout";
        let steer = json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "turn/steer",
            "params": {
                "threadId": thread_id,
                "expectedTurnId": turn_id,
                "input": input,
                "responsesapiClientMetadata": client_metadata,
            },
        });
        match exchange(
            &socket,
            trusted,
            &session_messages(thread_id, steer),
            deadline,
        ) {
            Ok(Some(response)) if !response.get("error").is_some_and(Value::is_object) => {
                return sent(thread_id, STRATEGY_STEER);
            }
            Err(Failure::Timeout) => return failed(thread_id, "turn_start_timeout"),
            _ => {}
        }
    }
    let turn = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "turn/start",
        "params": {
            "threadId": thread_id,
            "input": input,
            "responsesapiClientMetadata": client_metadata,
        },
    });
    match exchange(
        &socket,
        trusted,
        &session_messages(thread_id, turn),
        deadline,
    ) {
        Err(Failure::Timeout) => failed(thread_id, timeout_reason),
        Err(Failure::Error(name)) => failed(thread_id, name),
        Ok(None) => failed(thread_id, "missing_turn_start_response"),
        Ok(Some(response)) => match response.get("error") {
            Some(Value::Object(error)) => json!({
                "status": "failed",
                "reason": "turn_start_error",
                "message": error.get("message").and_then(Value::as_str).unwrap_or(REJECTED_MESSAGE),
                "thread_id": thread_id,
            }),
            _ => sent(thread_id, STRATEGY_TURN),
        },
    }
}

fn sent(thread_id: &str, strategy: &str) -> Value {
    let reason = if strategy == STRATEGY_STEER {
        "turn_steer_sent"
    } else {
        "turn_start_sent"
    };
    json!({
        "status": "sent",
        "reason": reason,
        "thread_id": thread_id,
        "strategy": strategy,
    })
}

fn failed(thread_id: &str, reason: &str) -> Value {
    json!({ "status": "failed", "reason": reason, "thread_id": thread_id })
}

/// `initialize`, `initialized` and `thread/resume`, then the continuation.
fn session_messages(thread_id: &str, continuation: Value) -> Vec<Value> {
    vec![
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "clientInfo": { "name": "hol-guard", "title": "HOL Guard", "version": "1.0.0" },
                "capabilities": {
                    "experimentalApi": true,
                    "optOutNotificationMethods": [
                        "thread/status/changed",
                        "turn/started",
                        "turn/completed",
                    ],
                },
            },
        }),
        json!({ "jsonrpc": "2.0", "method": "initialized", "params": {} }),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "thread/resume",
            "params": { "threadId": thread_id },
        }),
        continuation,
    ]
}

/// `build_codex_continuation_prompt`.
fn continuation_prompt(action: &str, request_id: &str, command_text: Option<&str>) -> String {
    match (action == "allow", command_text) {
        (true, Some(command)) => format!(
            "HOL Guard approved request `{request_id}` for this exact command:\n{command}\nRetry that exact command now using the existing saved approval."
        ),
        (true, None) => format!(
            "HOL Guard approved request `{request_id}`. Retry the blocked action now using the existing saved approval."
        ),
        (false, Some(command)) => format!(
            "HOL Guard blocked request `{request_id}` for this exact command:\n{command}\nDo not retry it. Explain a safe alternative."
        ),
        (false, None) => format!(
            "HOL Guard blocked request `{request_id}`. Do not retry that action. Explain a safe alternative."
        ),
    }
}

/// `_is_safe_codex_thread_id`.
fn is_safe_thread_id(thread_id: &str) -> bool {
    let length = thread_id.chars().count();
    (1..=256).contains(&length)
        && !thread_id.starts_with('-')
        && thread_id
            .chars()
            .all(|character| python_is_alphanumeric(character) || matches!(character, '-' | '_'))
}

/// Where a trusted socket may live, from the caller's own environment.
struct SocketRoots {
    home: Option<PathBuf>,
    cwd: Option<PathBuf>,
    roots: Vec<PathBuf>,
}

impl SocketRoots {
    fn new(request: &ContinueRequest<'_>) -> Self {
        let absolute = |text: Option<&str>| {
            text.filter(|text| Path::new(text).is_absolute())
                .map(PathBuf::from)
        };
        let home = absolute(request.home_dir);
        let mut roots: Vec<PathBuf> = vec![PathBuf::from("/tmp"), PathBuf::from("/var/tmp")];
        roots.extend(home.clone());
        roots.extend(absolute(request.temp_dir));
        let roots = roots
            .iter()
            .filter_map(|root| root.to_str())
            .map(|root| PathBuf::from(crate::oci_path::resolve_lenient(root)))
            .collect();
        Self {
            home,
            cwd: absolute(request.cwd),
            roots,
        }
    }

    /// `default_codex_app_server_socket_path` for a stored Codex home.
    fn default_socket(&self, codex_home: Option<&str>) -> Option<PathBuf> {
        let base = match codex_home {
            Some(codex_home) => self.absolute(codex_home)?,
            None => self.home.as_ref()?.join(".codex"),
        };
        Some(
            base.join("app-server-control")
                .join("app-server-control.sock"),
        )
    }

    /// `Path(text).expanduser()`, made absolute against the caller's cwd.
    fn absolute(&self, text: &str) -> Option<PathBuf> {
        if text.contains('\0') {
            return None;
        }
        let expanded = if text == "~" || text.starts_with("~/") {
            let home = self.home.as_ref()?;
            home.join(text[1..].trim_start_matches('/'))
        } else if let Some(user) = text.strip_prefix('~') {
            let (name, rest) = user.split_once('/').unwrap_or((user, ""));
            user_home(name)?.join(rest)
        } else {
            PathBuf::from(text)
        };
        let joined = if expanded.is_absolute() {
            expanded
        } else {
            self.cwd.as_ref()?.join(expanded)
        };
        Some(normalized(&joined))
    }

    /// `_is_safe_local_socket_path`: the resolved path is under one root.
    fn is_safe(&self, path: &Path) -> bool {
        let Some(text) = path.to_str() else {
            return false;
        };
        let resolved = PathBuf::from(crate::oci_path::resolve_lenient(text));
        self.roots.iter().any(|root| resolved.starts_with(root))
    }
}

/// `pathlib` spelling: repeated separators and `.` segments dropped.
fn normalized(path: &Path) -> PathBuf {
    path.components()
        .filter(|component| !matches!(component, Component::CurDir))
        .collect()
}

#[cfg(unix)]
fn user_home(name: &str) -> Option<PathBuf> {
    if name.is_empty() {
        return None;
    }
    nix::unistd::User::from_name(name)
        .ok()
        .flatten()
        .map(|user| user.dir)
}

#[cfg(not(unix))]
fn user_home(_name: &str) -> Option<PathBuf> {
    None
}

/// `_is_trusted_local_socket`: an owner-only socket in an owner-only directory.
#[cfg(unix)]
fn is_trusted_socket(path: &Path) -> bool {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let parent = path.parent().unwrap_or(Path::new("/"));
    let (Ok(socket), Ok(directory)) = (
        std::fs::symlink_metadata(path),
        std::fs::symlink_metadata(parent),
    ) else {
        return false;
    };
    let euid = nix::unistd::geteuid().as_raw();
    socket.file_type().is_socket()
        && socket.uid() == euid
        && socket.mode() & 0o022 == 0
        && directory.is_dir()
        && directory.uid() == euid
        && directory.mode() & 0o022 == 0
}

#[cfg(not(unix))]
fn is_trusted_socket(_path: &Path) -> bool {
    false
}

#[cfg(all(test, unix))]
#[path = "codex_thread_continue_vectors_tests.rs"]
mod vectors;
