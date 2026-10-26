//! The Claude Code permission notice for a review the resident queued.
//!
//! Once `pause_native_pre_tool_for_approval` pauses a Claude Code review for
//! the approval inbox (`prompted`), the daemon worker (`hook_worker_native.py`)
//! calls `record_claude_permission_notice_for_native_review`
//! (`hook_native_review_approval.py`), which builds the notice in
//! `_record_claude_permission_notice` (`commands_support_hook_state.py`) and
//! hands it to the `claude_record_notice` authority-state op. This builds the
//! same op arguments; `add_claude_native_review_approval_request` records them
//! in the queue's own transaction.

use super::super::query::{pre_tool_command, strip, tool_name};
use super::super::{Context, HookDirectDefer, ENVELOPE_BYTES, ESCAPE_FACTOR};
use super::{falsy_or_text, DEFAULT_REASON};
use base64ct::{Base64UrlUnpadded, Encoding};
use guard_command::hook_responses::Object;
use guard_contracts::HOOK_AUTHORITY_STATE_MAX_BYTES;
use serde_json::{json, Map, Value};

/// `_CLAUDE_GUARD_APPROVAL_HEADER` (`_commands_shared.py`).
const APPROVAL_HEADER: &str = "HOL Guard";
/// `_CLAUDE_GUARD_APPROVAL_OPTIONS` (`_commands_shared.py`).
const APPROVAL_OPTIONS: [&str; 3] = ["Allow once", "Allow during this session", "Keep blocked"];
/// `secrets.token_hex(6)`.
const APPROVAL_CODE_BYTES: usize = 6;

/// The `claude_record_notice` call `_record_claude_permission_notice` makes.
#[derive(Debug)]
pub(super) struct Notice {
    pub(super) session_id: String,
    /// `_optional_string(payload.get("tool_name"))`.
    pub(super) tool_name: Option<String>,
    pub(super) payload: Map<String, Value>,
}

/// `record_claude_permission_notice_for_native_review` followed by
/// `_record_claude_permission_notice`, for a workspace-scoped review, with
/// the clock (`_now`) and approval code (`secrets.token_hex(6)`) the call
/// reads. `None` when the hook names no session, so no notice is recorded.
pub(super) fn notice(
    harness: &str,
    payload: &Map<String, Value>,
    result: &Object,
    review_binding: Option<&str>,
    workspace: &str,
    saved_at: &str,
    approval_code: &str,
) -> Result<Option<Notice>, HookDirectDefer> {
    let Some(session_id) = optional_string(payload.get("session_id"))? else {
        return Ok(None);
    };
    let artifact_name = tool_name(payload)?;
    let command = pre_tool_command(payload)?;
    // `_native_review_artifact_id`.
    let artifact_id = format!("{harness}:native-pretool:{artifact_name}");
    let artifact_hash = review_binding
        .filter(|binding| !binding.is_empty())
        .unwrap_or(artifact_id.as_str())
        .to_owned();
    let reason = falsy_or_text(result.get("reason"), DEFAULT_REASON)?;
    let tool_name = optional_string(payload.get("tool_name"))?;
    let mut notice = Map::new();
    notice.insert("session_id".to_owned(), json!(session_id));
    notice.insert("saved_at".to_owned(), json!(saved_at));
    notice.insert("reason".to_owned(), json!(reason));
    notice.insert("artifact_hash".to_owned(), json!(artifact_hash));
    notice.insert("artifact_name".to_owned(), json!(artifact_name));
    notice.insert("artifact_type".to_owned(), json!("tool_call"));
    notice.insert("config_path".to_owned(), json!(workspace));
    notice.insert("source_scope".to_owned(), json!("project"));
    notice.insert("approval_header".to_owned(), json!(APPROVAL_HEADER));
    notice.insert(
        "approval_question".to_owned(),
        // `_claude_guard_approval_question_text`.
        json!(format!(
            "HOL Guard intercepted this sensitive action (approval code: {approval_code}). \
             What should Claude do?"
        )),
    );
    notice.insert("approval_options".to_owned(), json!(APPROVAL_OPTIONS));
    notice.insert("approval_code".to_owned(), json!(approval_code));
    // `_claude_artifact_command_binding`: the artifact's raw command text,
    // which is its command, or the artifact id.
    let binding = command
        .clone()
        .unwrap_or_else(|| format!("artifact:{artifact_id}"));
    notice.insert("command".to_owned(), json!(binding));
    if let Some(command) = command {
        notice.insert("raw_command_text".to_owned(), json!(command));
    }
    if let Some(tool_name) = &tool_name {
        notice.insert("tool_name".to_owned(), json!(tool_name));
    }
    notice.insert("artifact_id".to_owned(), json!(artifact_id));
    Ok(Some(Notice {
        session_id,
        tool_name,
        payload: notice,
    }))
}

/// The `claude_notice` arguments of `add_claude_native_review_approval_request`
/// for this hook, or `None` when the hook names no session. A notice this
/// binding holds no key for, or one whose op request could exceed the
/// daemon's limit, defers to the daemon.
pub(super) fn store_args(
    context: &Context<'_>,
    result: &Object,
    review_binding: Option<&str>,
) -> Result<Option<Value>, HookDirectDefer> {
    let saved_at =
        super::super::super::lifecycle::utc_now_isoformat().ok_or(HookDirectDefer::ReviewQueue)?;
    let mut code = [0u8; APPROVAL_CODE_BYTES];
    getrandom::fill(&mut code).map_err(|_| HookDirectDefer::ReviewQueue)?;
    let Some(notice) = notice(
        context.harness,
        context.recorded_payload,
        result,
        review_binding,
        context.workspace,
        &saved_at,
        &hex::encode(code),
    )?
    else {
        return Ok(None);
    };
    // `_policy_integrity_secret_material(create=True)` mints a key the
    // daemon has not bound yet; only the daemon can.
    let key = context
        .binding
        .integrity_key
        .as_ref()
        .ok_or(HookDirectDefer::ReviewQueue)?;
    let encoded = serde_json::to_vec(&notice.payload)
        .map_err(|_| HookDirectDefer::ReviewQueue)?
        .len()
        + notice.session_id.len()
        + notice.tool_name.as_ref().map_or(0, String::len)
        + saved_at.len() * 2
        + context.guard_home.len() * 2
        + key.key.len() * 2
        + key.key_id.len();
    if encoded * ESCAPE_FACTOR + ENVELOPE_BYTES > HOOK_AUTHORITY_STATE_MAX_BYTES {
        return Err(HookDirectDefer::ReviewQueue);
    }
    Ok(Some(json!({
        "now": saved_at,
        "session_id": notice.session_id,
        "tool_name": notice.tool_name,
        "payload": notice.payload,
        "integrity_key_b64": Base64UrlUnpadded::encode_string(&key.key),
        "integrity_key_id": key.key_id,
    })))
}

/// `_optional_string`: a string that is not blank, stripped.
fn optional_string(value: Option<&Value>) -> Result<Option<String>, HookDirectDefer> {
    match value.and_then(Value::as_str) {
        Some(text) => Ok(strip(text)?.map(str::to_owned)),
        None => Ok(None),
    }
}

#[cfg(test)]
#[path = "hook_direct_review_notice_tests.rs"]
mod tests;
