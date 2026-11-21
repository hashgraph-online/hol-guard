//! Exact-command block decisions for the resident direct hook.

use super::{lookup, render, Context, HookDirectDefer};
use crate::local_store_read::{open_read_only, pre_tool_command, STORE_FILE_NAME};
use guard_command::hook_responses::Object;
use guard_policy_snapshot::policy_integrity::is_remote_policy_source;
use serde_json::{json, Value};
use std::path::Path;

/// Apply a stored block for the exact shell command the daemon checks after
/// the edge. An unreadable store defers to the daemon's fail-closed lookup.
pub(super) fn exact_command_block_response(
    context: &Context<'_>,
    result: &Object,
) -> Result<Option<Value>, HookDirectDefer> {
    let Some(command) = pre_tool_command(context.payload) else {
        return Ok(None);
    };
    let candidates = crate::memory_pattern::verdict(&crate::memory_pattern::MemoryRequest {
        command: Some(command),
        artifact_type: Some("shell_command"),
        artifact_id: None,
        artifact_name: None,
        harness: None,
    });
    let store_path = Path::new(context.guard_home).join(STORE_FILE_NAME);
    let connection = open_read_only(&store_path)
        .map_err(|_| HookDirectDefer::SavedDecision)?
        .ok_or(HookDirectDefer::SavedDecision)?;
    let snapshot = connection
        .unchecked_transaction()
        .map_err(|_| HookDirectDefer::SavedDecision)?;
    for artifact_id in candidates.exact_artifact_ids {
        let lookup = lookup::policy_lookup(context, &snapshot, &artifact_id, None)?;
        let Some(decision) = lookup.get("decision").and_then(Value::as_object) else {
            continue;
        };
        if decision.get("scope").and_then(Value::as_str) != Some("artifact")
            || decision.get("artifact_id").and_then(Value::as_str) != Some(artifact_id.as_str())
            || decision.get("action").and_then(Value::as_str) != Some("block")
        {
            continue;
        }
        let remote = is_remote_policy_source(decision.get("source").and_then(Value::as_str));
        let mut blocked = result.clone();
        blocked.insert("decision".to_owned(), json!("deny"));
        blocked.insert("minimum_action".to_owned(), json!("block"));
        blocked.insert("policy_action".to_owned(), json!("block"));
        blocked.insert(
            "reason_code".to_owned(),
            json!(if remote {
                "policy_exact_command_block"
            } else {
                "saved_exact_command_block"
            }),
        );
        blocked.insert(
            "reason".to_owned(),
            json!(if remote {
                "Your Guard Cloud policy blocks this exact command. Do not retry it; continue with a permitted alternative."
            } else {
                "You chose to always block this exact command in HOL Guard. Do not retry it; continue with a permitted alternative."
            }),
        );
        return render(context.harness, &blocked, "blocked")
            .map(Some)
            .ok_or(HookDirectDefer::SavedDecision);
    }
    Ok(None)
}
