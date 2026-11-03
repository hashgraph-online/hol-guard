//! `memory_decision_receipt` runner-authority kind: the fields of the durable
//! receipt a memory decision event points at (the derivations in
//! `memory_decision_outbox._ensure_source_receipt_id` before they moved
//! here). Python keeps the store lookup and the receipt write.
//!
//! The request carries the approval request id, the person's decision, whether
//! the agent's retry could not reuse a one-time approval, and the request's
//! stripped `raw_command`, `artifact_id` and `artifact_hash` (each a string or
//! null). A decision that maps to no policy decision answers
//! `{"policy_decision": null}`; otherwise the answer names the policy
//! decision, the command text the receipt keeps, its artifact id and hash, the
//! user override and the deterministic receipt id.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::cloud_request_text::py_strip;
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const KEYS: [&str; 6] = [
    "request_id",
    "decision_action",
    "retry_blocked",
    "raw_command",
    "artifact_id",
    "artifact_hash",
];
/// The user approved once, but the agent's retry could not reuse that
/// approval, so the action stayed blocked. The dashboard reads this value.
const RETRY_BLOCKED_OVERRIDE: &str = "approval-approved-retry-blocked";
/// A tool call has no command text, and its review command then holds only
/// this wrapper, which is not the action.
const APPROVAL_WRAPPER_PREFIX: &str = "hol-guard approvals approve ";

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let fields = args_object(args)?;
    if fields.len() != KEYS.len() || !KEYS.iter().all(|key| fields.contains_key(*key)) {
        return Err(ERR_INVALID);
    }
    let request_id = fields
        .get("request_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(ERR_INVALID)?;
    let decision_action = fields
        .get("decision_action")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    let retry_blocked = fields
        .get("retry_blocked")
        .and_then(Value::as_bool)
        .ok_or(ERR_INVALID)?;
    let raw_command = nullable_text(fields, "raw_command")?;
    let artifact_id = nullable_text(fields, "artifact_id")?;
    let artifact_hash = nullable_text(fields, "artifact_hash")?;
    let policy_decision = match decision_action {
        "approved" => "allow",
        "blocked" => "block",
        "dismissed_keep_asking" => "require-reapproval",
        _ => return Ok(json!({"policy_decision": null})),
    };
    let raw_command =
        raw_command.filter(|command| !py_strip(command).starts_with(APPROVAL_WRAPPER_PREFIX));
    let artifact_id = artifact_id
        .map(str::to_owned)
        .unwrap_or_else(|| format!("approval-request:{request_id}"));
    let artifact_hash = artifact_hash.map(str::to_owned).unwrap_or_else(|| {
        let identity = raw_command.unwrap_or(artifact_id.as_str());
        format!("sha256:{}", sha256_hex(identity))
    });
    // A person made this decision; without an override the receipt reads as
    // "Guard allowed it automatically".
    let user_override = if retry_blocked && decision_action == "approved" {
        RETRY_BLOCKED_OVERRIDE.to_owned()
    } else {
        format!("approval-{decision_action}")
    };
    let digest = sha256_hex(&format!("{request_id}:{policy_decision}"));
    Ok(json!({
        "policy_decision": policy_decision,
        "raw_command": raw_command,
        "artifact_id": artifact_id,
        "artifact_hash": artifact_hash,
        "user_override": user_override,
        "receipt_id": format!("guard-receipt-memory-{}", &digest[..32]),
    }))
}

fn nullable_text<'a>(
    fields: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, &'static str> {
    match fields.get(key) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if !text.is_empty() => Ok(Some(text)),
        _ => Err(ERR_INVALID),
    }
}

fn sha256_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

#[cfg(test)]
#[path = "memory_decision_receipt_tests.rs"]
mod tests;
