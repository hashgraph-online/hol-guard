//! `HookDecide` `containment_rewrite` — the rewrite of a rendered PreToolUse
//! receipt into Guard's contained execution sink.
//!
//! When `containment_sink` names a profile, the resident writes a private
//! snapshot of the call and answers with an allow whose `updatedInput` runs
//! `guard execute-contained-test` on it, pinned by the snapshot's digest. The
//! snapshot sits in an owner-only directory under the temporary directory,
//! or on Windows under the profile's local temporary directory, which the
//! sink reads from whatever `TEMP` the harness shell sets. The transport only
//! names the argv that starts Guard's CLI.
//!
//! The sink rechecks native authority before it runs anything. A call whose
//! snapshot cannot be written or whose command cannot be quoted keeps its
//! receipt, so nothing here allows a call the sink would not run.

use guard_contracts::{ContainmentRewriteInputsV1, ContainmentRewriteV1, ContainmentSinkInputsV1};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::codex_hook_bridge::contain::{discard, resolved_workspace, write_snapshot};
use crate::hook_decision_containment_route::containment_sink;

const REQUEST_SCHEMA: &str = "guard-contained-test-request.v1";
const MAX_REQUEST_BYTES: usize = 1_048_576;
const ROUTED_REASON: &str = "native_contained_execution_routed";
/// Codex on Windows may run the sink in PowerShell or Git Bash; every other
/// harness runs it in a POSIX shell.
const BRIDGE_HARNESS: &str = "codex";

pub(crate) fn containment_rewrite(
    inputs: &ContainmentRewriteInputsV1,
) -> Result<ContainmentRewriteV1, String> {
    let sink = containment_sink(&sink_inputs(inputs))?;
    let response = match sink.profile {
        Some(_) => rewrite(inputs),
        None => None,
    };
    Ok(ContainmentRewriteV1 {
        profile: sink.profile,
        kept_because: sink.kept_because,
        response,
    })
}

fn sink_inputs(inputs: &ContainmentRewriteInputsV1) -> ContainmentSinkInputsV1 {
    ContainmentSinkInputsV1 {
        harness: inputs.harness.clone(),
        platform: inputs.platform.clone(),
        bridge: inputs.bridge,
        receipt_only: inputs.receipt_only,
        event_name: inputs.event_name.clone(),
        tool_name: inputs.tool_name.clone(),
        command_is_text: inputs
            .tool_input
            .get("command")
            .is_some_and(Value::is_string),
        decision: inputs.decision.clone(),
        policy_action: inputs.policy_action.clone(),
        reason_code: inputs.reason_code.clone(),
        required_execution_profile: inputs.required_execution_profile.clone(),
        observe_mode: inputs.observe_mode,
    }
}

/// The allow that runs the call in the sink, with its snapshot written, or
/// `None` with nothing left behind.
fn rewrite(inputs: &ContainmentRewriteInputsV1) -> Option<Value> {
    let original = inputs.tool_input.as_object()?;
    if inputs.sink_command.is_empty() {
        return None;
    }
    let workspace = resolved_workspace(inputs.workspace.as_deref()?)?;
    let serialized = serde_json::to_vec(&json!({
        "schema": REQUEST_SCHEMA,
        "workspace": workspace,
        "payload": {
            "hook_event_name": "PreToolUse",
            "tool_name": "bash",
            "tool_input": original,
            "cwd": workspace,
            "session_id": inputs.session_id,
            "tool_call_id": inputs.tool_call_id,
        },
    }))
    .ok()?;
    if serialized.len() > MAX_REQUEST_BYTES {
        return None;
    }
    let request = write_snapshot(&serialized)?;
    let Some(request_text) = request.to_str().map(str::to_owned) else {
        discard(&request);
        return None;
    };
    let digest = hex::encode(Sha256::digest(&serialized));
    let mut command = inputs.sink_command.clone();
    command.extend(
        [
            "guard",
            "execute-contained-test",
            "--harness",
            &inputs.harness,
            "--guard-home",
            &inputs.guard_home,
            "--workspace",
            &workspace,
            "--request-file",
            &request_text,
            "--request-sha256",
            &digest,
            "--home",
            &inputs.home,
        ]
        .map(str::to_owned),
    );
    let Some(joined) = shell_join(&inputs.harness, &command) else {
        discard(&request);
        return None;
    };
    Some(routed_response(original, joined))
}

/// The sink command line as the harness's shell reads it.
fn shell_join(harness: &str, command: &[String]) -> Option<String> {
    if harness == BRIDGE_HARNESS {
        return crate::codex_hook_bridge::contain::shell_join(command);
    }
    Some(crate::mcp_proxy_shlex::join(command))
}

fn routed_response(original: &Map<String, Value>, joined: String) -> Value {
    let mut updated = original.clone();
    updated.insert("command".to_owned(), Value::String(joined));
    json!({
        "policy_action": "allow",
        "reason_code": ROUTED_REASON,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "updatedInput": updated,
        },
    })
}

#[cfg(all(test, unix))]
#[path = "hook_decision_containment_rewrite_tests.rs"]
mod tests;
