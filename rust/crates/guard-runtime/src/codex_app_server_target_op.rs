//! `codex-app-server-target --stdin`: whether a recorded Codex target can be
//! continued in place, the retired Python `codex_app_server_target_reachable`.
//!
//! The request carries the stored operation metadata and the caller's own
//! home, temporary and working directories, which bound where a control
//! socket may live and how a relative one is read. The answer is
//! `{"reachable": bool}`; the check itself is
//! `codex_thread_continue_op::target_reachable`.

use std::io::Read;

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::codex_thread_continue_op::{target_reachable, ContinueRequest};

const MAX_REQUEST_BYTES: u64 = 1024 * 1024;

pub(crate) fn is_command(command: &str) -> bool {
    command == "codex-app-server-target"
}

#[derive(Deserialize)]
struct Request {
    metadata: Map<String, Value>,
    #[serde(default)]
    home_dir: Option<String>,
    #[serde(default)]
    temp_dir: Option<String>,
    #[serde(default)]
    cwd: Option<String>,
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "codex_app_server_target_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("codex_app_server_target_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes)
        .map_err(|_| "codex_app_server_target_request_invalid".to_owned())?;
    let probe = ContinueRequest {
        approval_request_id: "",
        action: "",
        home_dir: request.home_dir.as_deref(),
        temp_dir: request.temp_dir.as_deref(),
        cwd: request.cwd.as_deref(),
        timeout_ms: 0,
    };
    serde_json::to_vec(&json!({"reachable": target_reachable(&probe, &request.metadata)}))
        .map_err(|_| "codex_app_server_target_response_encode_failed".to_owned())
}

#[cfg(all(test, unix))]
#[path = "codex_app_server_target_op_tests.rs"]
mod tests;
