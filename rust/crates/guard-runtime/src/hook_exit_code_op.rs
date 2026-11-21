//! `hook-exit-code --stdin`: the process exit status a harness expects for a
//! resolved policy action, the retired Python `native_hook_verdict_exit_code`.
//!
//! The table is `hook_decision_directive::exit_code`; this op adds the two
//! facts that table leaves to its caller. An action outside the lattice is
//! normalized to the review tier, so a malformed value never reads as allow.
//! Grok exits 2 on a blocking verdict unless the caller reports that the Guard
//! home records protection as off (`recording_only`); Python reads that from
//! the store, which stays its concern. The answer is `{"exit_code": n}`.

use std::io::Read;

use guard_contracts::{normalize_guard_action, GuardAction};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::hook_decision_directive::{exit_code, is_blocking};

const MAX_REQUEST_BYTES: u64 = 16 * 1024;
const BLOCK: i32 = 2;

pub(crate) fn is_command(command: &str) -> bool {
    command == "hook-exit-code"
}

#[derive(Deserialize)]
struct Request {
    harness: String,
    #[serde(default)]
    policy_action: Value,
    #[serde(default)]
    event_name: Option<String>,
    #[serde(default)]
    recording_only: bool,
}

/// The exit status for `harness` after `action`, on `event_name`.
pub(crate) fn status(
    harness: &str,
    action: GuardAction,
    event_name: Option<&str>,
    recording_only: bool,
) -> i32 {
    if harness == "grok" {
        return if is_blocking(action) && !recording_only {
            BLOCK
        } else {
            0
        };
    }
    let event = event_name.unwrap_or(if harness == "zcode" { "PreToolUse" } else { "" });
    // Only grok has no row; every other harness answers.
    exit_code(harness, action, event).unwrap_or(BLOCK)
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "hook_exit_code_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("hook_exit_code_request_too_large".to_owned());
    }
    let request: Request =
        serde_json::from_slice(&bytes).map_err(|_| "hook_exit_code_request_invalid".to_owned())?;
    let action = normalize_guard_action(&request.policy_action, GuardAction::Review);
    let code = status(
        &request.harness,
        action,
        request.event_name.as_deref(),
        request.recording_only,
    );
    serde_json::to_vec(&json!({"exit_code": code}))
        .map_err(|_| "hook_exit_code_response_encode_failed".to_owned())
}

#[cfg(test)]
#[path = "hook_exit_code_op_tests.rs"]
mod tests;
