//! The daemon's approve-once retry for a reviewed `PreToolUse`.
//!
//! When no saved exact-action decision answers a review, the daemon spends a
//! five-minute "allow once" the user gave the same request in the approval
//! inbox: `native_review_matching_allow` (`hook_native_review_binding.py`)
//! with the review identity `native_review_binding`
//! (`hook_native_exact_action.py`) derives and the launch target of
//! `_native_review_launch_target` (`hook_native_review_approval.py`). The
//! resident runs the same `consume_native_review_approval` store operation the
//! daemon asks it for, under the same shared storage gate, and answers only
//! when it spent an approval. With no approval to spend, the resident queues
//! the review itself (`hook_direct_review_queue.rs`); every other outcome
//! defers to the daemon.

use super::query::{self, pre_tool_command, pre_tool_input, strip};
use super::{render, Context, HookDirectDefer};
use crate::local_store_read::STORE_FILE_NAME;
use fs2::FileExt;
use guard_command::hook_responses::Object;
use guard_contracts::{GuardStoreRequestV1, NativeExactActionQueryV1, GUARD_STORE_REQUEST_SCHEMA};
use serde_json::{json, Map, Value};
use std::fs::File;
use std::path::Path;

const CONSUME_METHOD: &str = "consume_native_review_approval";
/// The storage gate every daemon store call holds shared; maintenance that
/// replaces the store holds it exclusively.
const STORAGE_GATE_FILE_NAME: &str = "storage-access.lock";
/// The store files the daemon keeps private after each store call.
#[cfg(unix)]
const STORE_FILE_SUFFIXES: [&str; 4] = ["", "-journal", "-shm", "-wal"];
/// A hook waits this long for a busy store before the daemon takes over.
const BUSY_TIMEOUT_MS: u64 = 250;
const LAUNCH_TARGET_FIELDS: [&str; 4] = ["url", "path", "file_path", "target"];

/// The accepted allow for a review the resident spent an approve-once for,
/// or `None` when the store had no approve-once to spend.
pub(super) fn answer(
    context: &Context<'_>,
    result: &Object,
    exact: &NativeExactActionQueryV1,
    receipt: Option<&Value>,
    artifact_id: &str,
) -> Result<Option<Value>, HookDirectDefer> {
    let NativeExactActionQueryV1::ExactAction { tool_name, .. } = exact else {
        return Err(HookDirectDefer::SavedDecision);
    };
    let identity = crate::native_exact_action_op::review_binding_for(exact, receipt)
        .ok_or(HookDirectDefer::SavedDecision)?;
    let launch_target = launch_target(context.payload)?;
    let mut allowed = result.clone();
    for key in ["decision", "minimum_action", "policy_action"] {
        allowed.insert(key.to_owned(), json!("allow"));
    }
    // Rendered before the spend, so a spent approval always reaches the hook.
    let response =
        render(context.harness, &allowed, "accepted").ok_or(HookDirectDefer::SavedDecision)?;
    let guard_home = Path::new(context.guard_home);
    let _gate = storage_gate(guard_home)?;
    let mut args = Map::new();
    for (key, value) in [
        ("harness", context.harness),
        ("artifact_id", artifact_id),
        ("artifact_name", tool_name.as_str()),
        ("artifact_hash", identity.as_str()),
        ("launch_target", launch_target.as_str()),
        ("workspace", context.workspace),
    ] {
        args.insert(key.to_owned(), json!(value));
    }
    let now = super::super::lifecycle::utc_now_isoformat().ok_or(HookDirectDefer::SavedDecision)?;
    args.insert("now".to_owned(), json!(now));
    let mut request = GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: "direct-hook-review-consume".to_owned(),
        store_path: guard_home
            .join(STORE_FILE_NAME)
            .to_string_lossy()
            .into_owned(),
        guard_home: context.guard_home.to_owned(),
        method: "matching_native_review_block".to_owned(),
        source: "default".to_owned(),
        busy_timeout_ms: BUSY_TIMEOUT_MS,
        args,
    };
    let mut blocked = result.clone();
    for key in ["minimum_action", "policy_action"] {
        blocked.insert(key.to_owned(), json!("block"));
    }
    blocked.insert("decision".to_owned(), json!("deny"));
    blocked.insert("reason_code".to_owned(), json!("native_review_user_block"));
    blocked.insert("reason".to_owned(), json!("The user chose Keep blocked for this action. Do not retry it; continue with a permitted alternative."));
    let mut blocked_response =
        render(context.harness, &blocked, "blocked").ok_or(HookDirectDefer::SavedDecision)?;
    blocked_response
        .as_object_mut()
        .ok_or(HookDirectDefer::SavedDecision)?
        .insert("prompted".to_owned(), json!(false));
    let refused = crate::guard_store_op::evaluate(&request).map(|(payload, _)| payload);
    match refused {
        Ok(Value::Bool(true)) => {
            repair_store_permissions(guard_home);
            return Ok(Some(blocked_response));
        }
        Ok(Value::Bool(false)) => {}
        _ => return Err(HookDirectDefer::SavedDecision),
    }
    request.method = CONSUME_METHOD.to_owned();
    let spent = crate::guard_store_op::evaluate(&request).map(|(payload, _)| payload);
    repair_store_permissions(guard_home);
    match spent {
        Ok(Value::Bool(true)) => Ok(Some(response)),
        Ok(Value::Bool(false)) => Ok(None),
        _ => Err(HookDirectDefer::SavedDecision),
    }
}

/// `_native_review_launch_target`: the command as sent, else the first
/// non-blank target field stripped, else the tool.
fn launch_target(payload: &Map<String, Value>) -> Result<String, HookDirectDefer> {
    if let Some(command) = pre_tool_command(payload)? {
        return Ok(command);
    }
    if let Some(input) = pre_tool_input(payload) {
        for key in LAUNCH_TARGET_FIELDS {
            if let Some(value) = input.get(key).and_then(Value::as_str) {
                if let Some(stripped) = strip(value)? {
                    return Ok(stripped.to_owned());
                }
            }
        }
    }
    Ok(format!("tool:{}", query::tool_name(payload)?))
}

/// The daemon's storage gate, held shared until the spend commits. A gate
/// the daemon has not created yet, or one held exclusively, defers.
pub(super) fn storage_gate(guard_home: &Path) -> Result<File, HookDirectDefer> {
    let gate = open_no_follow(&guard_home.join(STORAGE_GATE_FILE_NAME))
        .ok_or(HookDirectDefer::SavedDecision)?;
    FileExt::try_lock_shared(&gate).map_err(|_| HookDirectDefer::SavedDecision)?;
    Ok(gate)
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> Option<File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .ok()
}

#[cfg(not(unix))]
fn open_no_follow(_path: &Path) -> Option<File> {
    None
}

/// `_repair_store_permissions`: the store files stay owner-only, including a
/// journal this connection created.
#[cfg(unix)]
pub(super) fn repair_store_permissions(guard_home: &Path) {
    use std::os::unix::fs::PermissionsExt;
    for suffix in STORE_FILE_SUFFIXES {
        let path = guard_home.join(format!("{STORE_FILE_NAME}{suffix}"));
        if std::fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.is_file()) {
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
    }
}

#[cfg(not(unix))]
pub(super) fn repair_store_permissions(_guard_home: &Path) {}

#[cfg(test)]
#[path = "hook_direct_saved_consume_tests.rs"]
mod tests;
