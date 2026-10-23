//! Signed public-task prompt relation from Python private-cell runtime custody.
//! Native hook, product and kernel provenance remain separate requirements.

use crate::crypto::sha256;
use crate::{canonical_value, verify_controller_envelope, EvidenceError, Result};
use serde_json::{json, Value};

const CONTEXT_COUNT: &str = "exact normal MCP task context required";
const CONTEXT: &str = "MCP normal public task context differs";
const DENIED: &str = "MCP public task review did not admit this context";
const BOUNDARY: &str = "MCP task hook escaped its product boundary";
const PROMPT: &str = "builtin task prompt lacks matching actual native admission";

fn child(envelope: &Value, key: &[u8]) -> Result<Value> {
    let raw = serde_json::to_vec(envelope)
        .map_err(|_| EvidenceError::Invalid("invalid controller envelope"))?;
    verify_controller_envelope(&raw, key)
}

fn digest(value: &Value) -> Result<String> {
    Ok(sha256(&canonical_value(value)?))
}

/// Match Python's public-prompt relation over an outer runtime, builtin, MCP
/// and task-context envelope signed by one externally pinned controller key.
/// The native `_hook` validator is not ported by this function: an `allow`
/// field here is still only a signed producer report, never an execution pass.
pub fn verify_private_runtime_prompt_relation(
    raw_runtime: &[u8],
    outside_public_key: &[u8],
    outside_session_id: &str,
    outside_prompt_digest: &str,
) -> Result<Value> {
    if raw_runtime.len() > 24 * 1024 * 1024 {
        return Err(EvidenceError::Invalid(
            "bounded signed runtime evidence required",
        ));
    }
    let record = verify_controller_envelope(raw_runtime, outside_public_key)?;
    let builtin = child(
        record
            .get("native_builtin_audit")
            .ok_or(EvidenceError::Invalid(CONTEXT))?,
        outside_public_key,
    )?;
    let mcp = child(
        record
            .get("native_mcp_audit")
            .ok_or(EvidenceError::Invalid(CONTEXT))?,
        outside_public_key,
    )?;
    let plane = builtin
        .get("product_plane")
        .ok_or(EvidenceError::Invalid(CONTEXT))?;
    let contexts = record
        .get("native_task_contexts")
        .and_then(Value::as_array)
        .ok_or(EvidenceError::Invalid(CONTEXT_COUNT))?;
    if contexts.len() != 1 {
        return Err(EvidenceError::Invalid(CONTEXT_COUNT));
    }
    let context = child(&contexts[0], outside_public_key)?;
    let hooks = context
        .get("hooks")
        .and_then(Value::as_array)
        .ok_or(EvidenceError::Invalid(CONTEXT))?;
    let public_prompt = context
        .get("public_prompt")
        .ok_or(EvidenceError::Invalid(CONTEXT))?;
    if context.get("phase") != Some(&Value::String("developer".into()))
        || context.get("public_prompt_digest") != Some(&Value::String(outside_prompt_digest.into()))
        || digest(public_prompt)? != outside_prompt_digest
        || hooks.len() != 1
    {
        return Err(EvidenceError::Invalid(CONTEXT));
    }
    let hook = &hooks[0];
    if hook.get("response").and_then(|row| row.get("decision"))
        != Some(&Value::String("allow".into()))
    {
        return Err(EvidenceError::Invalid(DENIED));
    }
    let actor = mcp
        .get("product_plane")
        .and_then(|plane| plane.get("observations"))
        .and_then(Value::as_array)
        .and_then(|rows| {
            rows.iter()
                .find(|row| row.get("kind") == Some(&json!("container-boundary")))
        })
        .and_then(|row| row.get("identity"))
        .ok_or(EvidenceError::Invalid(BOUNDARY))?;
    let identity = hook
        .get("identity")
        .ok_or(EvidenceError::Invalid(BOUNDARY))?;
    if [
        "boot_id",
        "mount_namespace",
        "pid_namespace",
        "network_namespace",
    ]
    .iter()
    .any(|name| identity.get(*name).is_none() || identity.get(*name) != actor.get(*name))
    {
        return Err(EvidenceError::Invalid(BOUNDARY));
    }
    let payload = json!({
        "hook_event_name": "UserPromptSubmit",
        "prompt": public_prompt,
        "config_path": "/product/home/omp.json",
        "session_id": outside_session_id,
    });
    let payload_digest = digest(&payload)?;
    let prompts: Vec<&Value> = builtin
        .get("transport_observations")
        .and_then(Value::as_array)
        .ok_or(EvidenceError::Invalid(PROMPT))?
        .iter()
        .filter(|row| row.get("kind") == Some(&json!("actual-user-prompt-response")))
        .collect();
    let native_hooks = plane
        .get("hooks")
        .and_then(Value::as_array)
        .ok_or(EvidenceError::Invalid(PROMPT))?;
    if prompts.len() != 1
        || prompts[0].get("payload_digest") != Some(&json!(payload_digest))
        || prompts[0]
            .get("product_response")
            .and_then(|row| row.get("decision"))
            != Some(&json!("allow"))
        || !native_hooks.iter().any(|row| {
            row.get("payload_digest") == Some(&json!(payload_digest))
                && row.get("response_digest") == prompts[0].get("response_digest")
        })
    {
        return Err(EvidenceError::Invalid(PROMPT));
    }
    Ok(json!({"matched_public_prompts": 1, "execution_eligible": false}))
}
