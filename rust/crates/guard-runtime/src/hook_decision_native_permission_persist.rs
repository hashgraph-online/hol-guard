//! `HookDecide` `native_permission_persist_plan` — what a Claude-native
//! approval saves.
//!
//! The stored hash is what a saved approval is looked up by, so it is decided
//! here and nowhere else: a well-formed approval-context token is stored as
//! it is, and anything else is stored as the runtime exact-match key of the
//! command (bound to the action's config path, scope, command text and
//! wrapper chain), falling back to the raw hash when the artifact has no
//! exact-match key. The transport performs the writes the plan names.

use guard_command::hook_adapter_paths::{expanded_text, PathEnv};
use guard_contracts::{
    GuardAction, NativePermissionEventV1, NativePermissionPersistInputsV1,
    NativePermissionPersistPlanV1,
};
use serde_json::{json, Value};

use crate::context_digest::parse_context_token;
use crate::guard_store_json::dumps_sorted;
use crate::hook_decision_finalize::parse_action;
use crate::policy_decision_lookup_op::runtime_scoped_exact_match_key;

const EXACT_KEY_MISSING_EVENT: &str = "claude/native_permission_exact_key_missing";
const SAVED_EVENT: &str = "claude/native_permission_saved";
const RETAINED_EVENT: &str = "claude/native_permission_current_policy_retained";
const TOOL_ACTION_REQUEST: &str = "tool_action_request";
const PATH_UNSUPPORTED: &str = "native_hook_decision_context_path_unsupported";
const CONTEXT_INVALID: &str = "native_hook_decision_context_invalid";

fn event(name: &str, before_policy: bool, payload: Value) -> NativePermissionEventV1 {
    let Value::Object(payload) = payload else {
        unreachable!("event payloads are objects");
    };
    NativePermissionEventV1 {
        name: name.to_owned(),
        payload,
        before_policy,
    }
}

fn non_empty(text: Option<&str>) -> Option<&str> {
    text.filter(|text| !text.is_empty())
}

/// `runtime_tool_action_exact_match_context`: the compact, sorted JSON of the
/// action's location and command, or `None` when it has none of them.
fn exact_match_context(inputs: &NativePermissionPersistInputsV1) -> Result<Option<String>, String> {
    let config_path = non_empty(inputs.config_path.as_deref());
    let source_scope = inputs.source_scope.as_deref();
    // Only a string command text and an array wrapper chain count.
    let raw_command_text = inputs.raw_command_text.as_ref().and_then(Value::as_str);
    let wrapper_chain = inputs.wrapper_chain.as_ref().and_then(Value::as_array);
    if config_path.is_none()
        && non_empty(source_scope).is_none()
        && non_empty(raw_command_text).is_none()
        && wrapper_chain.is_none_or(|chain| chain.is_empty())
    {
        return Ok(None);
    }
    let env = PathEnv {
        tilde_home: inputs.tilde_home.clone(),
        default_home: None,
        cwd: None,
    };
    let config_path = config_path
        .map(|path| expanded_text(path, &env).map_err(|_| PATH_UNSUPPORTED.to_owned()))
        .transpose()?;
    let wrapper_chain: Vec<&str> = wrapper_chain
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|item| !item.is_empty())
        .collect();
    let context = json!({
        "config_path": config_path,
        "source_scope": source_scope,
        "raw_command_text": raw_command_text,
        "wrapper_chain": wrapper_chain,
        "permission_mode": null,
    });
    dumps_sorted(&context)
        .map(Some)
        .ok_or_else(|| CONTEXT_INVALID.to_owned())
}

fn is_context_token(artifact_hash: &str) -> bool {
    parse_context_token(&Value::String(artifact_hash.to_owned())).is_some()
}

/// The approval saved as a policy row, with the events around it.
fn saved(
    inputs: &NativePermissionPersistInputsV1,
    inventory_approved: bool,
) -> Result<NativePermissionPersistPlanV1, String> {
    let tool_action = inputs.artifact_type.as_deref() == Some(TOOL_ACTION_REQUEST);
    let exact_key = if tool_action {
        let context = exact_match_context(inputs)?;
        runtime_scoped_exact_match_key(Some(inputs.artifact_id.as_str()), context.as_deref())
    } else {
        None
    };
    let stored = if is_context_token(&inputs.artifact_hash) {
        inputs.artifact_hash.clone()
    } else {
        exact_key
            .clone()
            .unwrap_or_else(|| inputs.artifact_hash.clone())
    };
    let mut events = Vec::new();
    if tool_action && exact_key.is_none() {
        events.push(event(
            EXACT_KEY_MISSING_EVENT,
            true,
            json!({
                "artifact_id": inputs.artifact_id,
                "artifact_type": TOOL_ACTION_REQUEST,
                "source": inputs.source,
            }),
        ));
    }
    events.push(event(
        SAVED_EVENT,
        false,
        json!({
            "artifact_id": inputs.artifact_id,
            "artifact_hash": stored,
            "action": inputs.action,
            "reason": inputs.reason,
        }),
    ));
    let policy_action = if inputs.action == "allow" {
        "allow"
    } else {
        "block"
    };
    Ok(NativePermissionPersistPlanV1 {
        stored_artifact_hash: Some(stored),
        policy_action: Some(policy_action.to_owned()),
        events,
        inventory_approved,
    })
}

/// The current policy stays in force: no policy row, one audit event.
fn retained(
    inputs: &NativePermissionPersistInputsV1,
    current: GuardAction,
) -> NativePermissionPersistPlanV1 {
    NativePermissionPersistPlanV1 {
        stored_artifact_hash: None,
        policy_action: None,
        events: vec![event(
            RETAINED_EVENT,
            false,
            json!({
                "artifact_id": inputs.artifact_id,
                "artifact_hash": inputs.artifact_hash,
                "native_action": inputs.action,
                "authoritative_action": current.as_str(),
            }),
        )],
        inventory_approved: current == GuardAction::Warn,
    }
}

pub(crate) fn native_permission_persist_plan(
    inputs: &NativePermissionPersistInputsV1,
) -> Result<NativePermissionPersistPlanV1, String> {
    let current = inputs
        .authoritative_action
        .as_deref()
        .map(parse_action)
        .transpose()?;
    match current {
        // The user's answer is saved outright, or the current policy agrees.
        None => saved(inputs, false),
        Some(GuardAction::Allow) => saved(inputs, true),
        Some(current) => Ok(retained(inputs, current)),
    }
}

#[cfg(test)]
#[path = "hook_decision_native_permission_persist_tests.rs"]
mod tests;
