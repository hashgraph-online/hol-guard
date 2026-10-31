//! `ReviewRequest` — the approval request a paused native review queues.
//!
//! The daemon pauses a reviewed `PreToolUse` it cannot settle and queues it in
//! the approval inbox. This builds that request: the tool name and launch
//! target, the review envelope with its command category, validated origin receipt and
//! exact-action keys, the native Bash descriptor of a bound script review, and
//! every `GuardApprovalRequest` field the queue sets. The daemon still checks
//! the policy binding, reads the allow hint and writes the request.

use super::{envelope_map, ref_digests, Failure};
use crate::daemon_lifecycle_text::py_strip;
use crate::hook_direct::saved_decision::review_request::{
    result_command_category, review_envelope, tagged,
};
use crate::{native_decision_receipt, pyjson};
use guard_command::hook_adapter_value::{OMap, OValue};
use guard_contracts::{
    ReviewRequestQueryV1, NATIVE_BASH_ARTIFACT_ID, NATIVE_BASH_REVIEW_ARTIFACT_TYPE,
    NATIVE_BASH_REVIEW_DESCRIPTOR_SCHEMA,
};
use serde_json::{json, Map, Value};

const INVALID: &str = "native_hook_adapter_review_invalid";
const DEFAULT_REASON: &str = "HOL Guard requires review before this action can execute.";
/// What a bound script review adds to its reason.
const BOUND_BASH_REASON: &str =
    " Keep blocked applies to this request's retries for up to 24 hours; a new user request is separate.";
const TOOL_NAME_FIELDS: [&str; 3] = ["tool_name", "toolName", "tool"];
const TOOL_INPUT_FIELDS: [&str; 2] = ["tool_input", "toolInput"];
const COMMAND_FIELDS: [&str; 4] = ["command", "cmd", "shell_command", "shellCommand"];
const LAUNCH_TARGET_FIELDS: [&str; 4] = ["url", "path", "file_path", "target"];
const EXACT_ACTION_CONTEXT_TOKEN_KEY: &str = "exact_context_token";
const EXACT_ACTION_IDENTITY_KIND_KEY: &str = "exact_identity_kind";
const ONCE_ONLY_REASON_KEY: &str = "once_only_reason";

fn invalid() -> Failure {
    Failure::code(INVALID)
}

/// The `GuardApprovalRequest` fields the queue sets, in the adapter's wire form.
pub(super) fn review_request(query: &ReviewRequestQueryV1) -> Result<Value, Failure> {
    let built = build(query)?;
    let request =
        OValue::from_wire(&tagged(&Value::Object(built.request))).map_err(Failure::code)?;
    Ok(request.to_wire_with_refs(&ref_digests(&built.payload)))
}

/// A paused review's request as plain JSON, with the hook payload it read.
pub(crate) struct Built {
    /// The `GuardApprovalRequest` fields the queue sets.
    pub(crate) request: Map<String, Value>,
    /// The hook payload as plain JSON.
    pub(crate) fields: Map<String, Value>,
    payload: OMap,
}

/// The request [`review_request`] answers, before its wire encoding.
pub(crate) fn build(query: &ReviewRequestQueryV1) -> Result<Built, Failure> {
    let (envelope, payload) = envelope_map(&query.envelope)?;
    let Value::Object(fields) = plain(&OValue::Map(payload.clone()))? else {
        return Err(invalid());
    };
    let mut envelope = review_envelope(plain(&OValue::Map(envelope))?).ok_or_else(invalid)?;
    let result = query.result.as_object().ok_or_else(invalid)?;
    if matches!(envelope.get("command_category"), None | Some(Value::Null)) {
        if let Some(category) = result_command_category(result) {
            envelope.insert("command_category".to_owned(), Value::String(category));
        }
    }
    if let Some(receipt) = query
        .native_receipt
        .as_ref()
        .filter(|receipt| origin_receipt(receipt))
    {
        envelope.insert("native_origin_receipt".to_owned(), receipt.clone());
    }
    let tool_name = tool_name(&fields);
    let command = pre_tool_command(&fields);
    if let Some(token) = &query.exact_token {
        envelope.insert(EXACT_ACTION_CONTEXT_TOKEN_KEY.to_owned(), json!(token));
        if command.is_none() {
            envelope.insert(
                EXACT_ACTION_IDENTITY_KIND_KEY.to_owned(),
                json!("tool-target"),
            );
        }
    } else if let Some(reason) = &query.once_only_reason {
        envelope.insert(ONCE_ONLY_REASON_KEY.to_owned(), json!(reason));
    }
    let mut reason = reason(result)?;
    let harness = &query.envelope.harness;
    let (artifact_id, artifact_type, queue_group_id) = match &query.bound_bash {
        Some(bound) => {
            let lineage = bound.get("review_lineage").ok_or_else(invalid)?;
            let lineage_id = lineage
                .get("lineage_id")
                .and_then(Value::as_str)
                .ok_or_else(invalid)?;
            reason.push_str(BOUND_BASH_REASON);
            envelope.insert(
                "native_bash".to_owned(),
                json!({
                    "schema": NATIVE_BASH_REVIEW_DESCRIPTOR_SCHEMA,
                    "artifact_id": NATIVE_BASH_ARTIFACT_ID,
                    "artifact_hash": query.exact_token,
                    "subject": bound.get("subject").ok_or_else(invalid)?,
                    "review_lineage": lineage,
                }),
            );
            (
                NATIVE_BASH_ARTIFACT_ID.to_owned(),
                NATIVE_BASH_REVIEW_ARTIFACT_TYPE,
                Some(format!("native-bash-review:{lineage_id}")),
            )
        }
        None => (
            format!("{harness}:native-pretool:{tool_name}"),
            "tool_call",
            query.queue_group_id.clone(),
        ),
    };
    let request_id = query.request_id.as_str();
    let workspace = query.envelope.workspace.as_deref();
    let request = json!({
        "request_id": request_id,
        "harness": harness,
        "artifact_id": artifact_id,
        "artifact_name": tool_name,
        "artifact_hash": query
            .review_binding
            .as_deref()
            .filter(|binding| !binding.is_empty())
            .unwrap_or(request_id),
        "policy_action": "review",
        "recommended_scope": "artifact",
        "changed_fields": ["native_pre_tool"],
        "source_scope": if workspace.is_some() { "project" } else { "harness" },
        "config_path": workspace.unwrap_or(query.guard_home.as_str()),
        "review_command": format!("hol-guard approvals approve {request_id}"),
        "approval_url": format!("{}/requests/{request_id}", query.approval_center_url),
        "workspace": workspace,
        "artifact_type": artifact_type,
        "launch_target": launch_target(&fields, command.as_deref(), &tool_name),
        "risk_summary": reason,
        "action_envelope_json": envelope,
        "raw_command_text": command,
        "queue_group_id": queue_group_id,
    });
    let Value::Object(request) = request else {
        return Err(invalid());
    };
    Ok(Built {
        request,
        fields,
        payload,
    })
}

/// A valid receipt that authenticates its origin; the envelope keeps only that.
fn origin_receipt(receipt: &Value) -> bool {
    receipt.get("origin_authentication").is_some()
        && pyjson::parse(&receipt.to_string())
            .is_ok_and(|receipt| native_decision_receipt::valid(&receipt))
}

/// The ordered `value` as plain JSON.
fn plain(value: &OValue) -> Result<Value, Failure> {
    serde_json::from_str(&value.compact_json()).map_err(|_| invalid())
}

/// `str(native_result.get("reason") or DEFAULT_REASON)` for the reasons a
/// native result carries.
fn reason(result: &Map<String, Value>) -> Result<String, Failure> {
    match result.get("reason") {
        None | Some(Value::Null) | Some(Value::Bool(false)) => Ok(DEFAULT_REASON.to_owned()),
        Some(Value::String(text)) if text.is_empty() => Ok(DEFAULT_REASON.to_owned()),
        Some(Value::String(text)) => Ok(text.clone()),
        Some(_) => Err(invalid()),
    }
}

/// `native_review_tool_name`: the first non-blank tool name, stripped.
pub(crate) fn tool_name(payload: &Map<String, Value>) -> String {
    TOOL_NAME_FIELDS
        .iter()
        .filter_map(|key| payload.get(*key).and_then(Value::as_str))
        .map(py_strip)
        .find(|name| !name.is_empty())
        .unwrap_or("tool")
        .to_owned()
}

/// `pre_tool_input`.
pub(crate) fn pre_tool_input(payload: &Map<String, Value>) -> Option<&Map<String, Value>> {
    TOOL_INPUT_FIELDS
        .iter()
        .find_map(|key| payload.get(*key).and_then(Value::as_object))
}

/// `pre_tool_command`: the first non-blank command text, unstripped.
pub(crate) fn pre_tool_command(payload: &Map<String, Value>) -> Option<String> {
    let arguments = payload.get("arguments").and_then(Value::as_object);
    [pre_tool_input(payload), arguments, Some(payload)]
        .into_iter()
        .flatten()
        .flat_map(|candidate| {
            COMMAND_FIELDS
                .iter()
                .filter_map(move |key| candidate.get(*key).and_then(Value::as_str))
        })
        .find(|command| !py_strip(command).is_empty())
        .map(str::to_owned)
}

/// `_native_review_launch_target`: the command, else the first named target
/// in the tool input, else the tool.
fn launch_target(payload: &Map<String, Value>, command: Option<&str>, tool_name: &str) -> String {
    if let Some(command) = command {
        return command.to_owned();
    }
    pre_tool_input(payload)
        .and_then(|input| {
            LAUNCH_TARGET_FIELDS
                .iter()
                .filter_map(|key| input.get(*key).and_then(Value::as_str))
                .map(py_strip)
                .find(|target| !target.is_empty())
        })
        .map_or_else(|| format!("tool:{tool_name}"), str::to_owned)
}

#[cfg(test)]
#[path = "hook_adapter_review_request_tests.rs"]
mod tests;
