//! `queue_native_review`: the paused native review's approval request, built
//! and queued in one store call.
//!
//! `queue_native_pre_tool_review` (`hook_native_review_approval.py`) used to
//! ask the resident for the request (`review_request`), assemble the
//! `GuardApprovalRequest` with its allow hint, and send it back for the queue
//! write. This builds the same request here and rewrites the call into the
//! queue write it used to make:
//!
//! - `add_silent_native_review_approval_request` (with `daemon`) for a review
//!   the agent never sees;
//! - `add_claude_approval_request` for a prompted Claude Code review that
//!   carries its notice's integrity key;
//! - `add_approval_request` otherwise.
//!
//! The rewrite runs before the store opens its write, so the Codex live wait
//! and the read-back behave exactly as for the method it names.

use guard_contracts::ReviewRequestQueryV1;
use serde_json::{json, Map, Value};
use zeroize::Zeroize;

use crate::guard_store_db::{StoreError, StoreResult};
use crate::hook_adapter_op::review_request::{self, pre_tool_command};

pub(crate) const METHOD: &str = "queue_native_review";

const INVALID: StoreError = StoreError::Invalid("native_guard_store_review_queue_invalid");
/// The resident could not build the review's request from a well-formed
/// query; the hook fails closed and logs this code.
const REFUSED: StoreError = StoreError::Invalid("native_guard_store_review_request_refused");
/// What the notice reads from the hook payload besides the command: the
/// session and the tool name fields.
const NOTICE_PAYLOAD_FIELDS: [&str; 4] = ["session_id", "tool_name", "toolName", "tool"];

/// The queue write a `queue_native_review` call stands for.
pub(crate) struct Delegated {
    pub(crate) method: &'static str,
    pub(crate) args: Map<String, Value>,
}

impl Drop for Delegated {
    /// Wipe this copy of the notice key the call carried.
    fn drop(&mut self) {
        if let Some(Value::String(key)) = self.args.get_mut("integrity_key_b64") {
            key.zeroize();
        }
    }
}

/// The queue method and arguments a `queue_native_review` call stands for.
pub(crate) fn delegate(args: &Map<String, Value>) -> StoreResult<Delegated> {
    let mut delegated = args.clone();
    let query: ReviewRequestQueryV1 =
        serde_json::from_value(delegated.remove("review").ok_or(INVALID)?).map_err(|_| INVALID)?;
    let hint = delegated
        .remove("extension_allow_hint")
        .unwrap_or(Value::Null);
    let silent = take_flag(&mut delegated, "silent")?;
    let claude_notice = take_flag(&mut delegated, "claude_notice")?;
    if !(hint.is_null() || hint.is_object()) || (silent && claude_notice) {
        return Err(INVALID);
    }
    let built = review_request::build(&query).map_err(|_| REFUSED)?;
    let mut request = built.request;
    request.insert("extension_allow_hint".to_owned(), hint);
    let method = if silent {
        delegated.insert("daemon".to_owned(), Value::Bool(true));
        "add_silent_native_review_approval_request"
    } else if claude_notice && delegated.contains_key("integrity_key_b64") {
        let review = notice_review(&query, &request, &built.fields);
        delegated.insert("claude_review".to_owned(), review);
        "add_claude_approval_request"
    } else {
        // Without a key the review still queues; the hook falls back to its
        // ordinary prompt.
        delegated.remove("integrity_key_b64");
        delegated.remove("integrity_key_id");
        "add_approval_request"
    };
    delegated.insert("request".to_owned(), Value::Object(request));
    Ok(Delegated {
        method,
        args: delegated,
    })
}

fn take_flag(args: &mut Map<String, Value>, key: &str) -> StoreResult<bool> {
    match args.remove(key) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(flag)) => Ok(flag),
        Some(_) => Err(INVALID),
    }
}

/// The `claude_review` facts `add_claude_approval_request` signs a notice
/// from. The hook payload carries only what the notice reads, so the command
/// is not copied in full a second time.
fn notice_review(
    query: &ReviewRequestQueryV1,
    request: &Map<String, Value>,
    fields: &Map<String, Value>,
) -> Value {
    let mut hook_payload: Map<String, Value> = NOTICE_PAYLOAD_FIELDS
        .iter()
        .filter_map(|name| Some(((*name).to_owned(), fields.get(*name)?.clone())))
        .collect();
    if let Some(command) = pre_tool_command(fields) {
        hook_payload.insert("tool_input".to_owned(), json!({ "command": command }));
    }
    json!({
        "harness": query.envelope.harness,
        "hook_payload": hook_payload,
        "reason": query.result.get("reason").cloned().unwrap_or(Value::Null),
        "review_binding": query.review_binding,
        "config_path": request.get("config_path").cloned().unwrap_or(Value::Null),
        "source_scope": request.get("source_scope").cloned().unwrap_or(Value::Null),
    })
}

#[cfg(test)]
#[path = "guard_store_native_review_queue_tests.rs"]
mod tests;
