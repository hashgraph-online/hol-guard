//! `CommandCapabilityIssue` - resident op that decides which operations a new
//! Guard Cloud command capability may carry.
//!
//! Faithful port of the validation `runtime/command_capability.py`'s
//! `issue_command_capability` performed before it signed an envelope, and of
//! the `read-only` expansion `cli/commands_dispatch_cloud.py` performed before
//! calling it. Both sides decided what a grant could authorize, so a caller
//! reaching either one could mint a capability naming an operation the runtime
//! would refuse to honor. The runtime now answers the whole question from the
//! words the user typed; the caller signs and stores what it is told.
//!
//! Refusal codes are the Python ones verbatim: `hol-guard commands enable`
//! prints them and the cloud command audit trail records them.

use std::collections::BTreeSet;

use guard_contracts::{
    command_operation_is_classified, CommandCapabilityIssueRequestV1,
    CommandCapabilityIssueResultV1, COMMAND_CAPABILITY_ISSUE_MAX_BYTES,
    COMMAND_CAPABILITY_ISSUE_REQUEST_SCHEMA, COMMAND_CAPABILITY_ISSUE_RESULT_SCHEMA,
    COMMAND_CAPABILITY_MAX_TTL_SECONDS, EXACT_CLOUD_REVIEW_OPERATION,
    POLICY_MEMORY_COMMAND_OPERATIONS, READ_ONLY_COMMAND_OPERATIONS,
    READ_ONLY_COMMAND_OPERATION_GROUP,
};
use serde_json::{json, Value};

use crate::package_authority_op::request_digest_with_limit;

pub(crate) fn evaluate_command_capability_issue_request(
    request: &CommandCapabilityIssueRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)
        .map_err(|_| "native_command_capability_issue_too_large".to_owned())?;
    // A request naming another contract is not this op's to answer: the field
    // is the sender's own statement of which request shape it built.
    let (status, code, payload) = if request.schema != COMMAND_CAPABILITY_ISSUE_REQUEST_SCHEMA {
        (
            "error",
            "native_command_capability_issue_schema_mismatch",
            None,
        )
    } else {
        ("ok", "ok", Some(issued(request)))
    };
    crate::encode_response(&CommandCapabilityIssueResultV1 {
        schema: COMMAND_CAPABILITY_ISSUE_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        payload,
    })
}

fn request_digest(request: &CommandCapabilityIssueRequestV1) -> Result<String, String> {
    let material = serde_json::to_value(request)
        .map_err(|_| "native_command_capability_issue_invalid".to_owned())?;
    request_digest_with_limit(&material, COMMAND_CAPABILITY_ISSUE_MAX_BYTES)
}

fn issued(request: &CommandCapabilityIssueRequestV1) -> Value {
    match admitted(request) {
        Err(reason) => json!({
            "granted": false,
            "reason": reason,
            "operations": Vec::<String>::new(),
        }),
        Ok(operations) => json!({
            "granted": true,
            "reason": Value::Null,
            "operations": operations,
        }),
    }
}

/// The exact operations the capability may carry, or the code that refused it.
fn admitted(request: &CommandCapabilityIssueRequestV1) -> Result<Vec<String>, &'static str> {
    if request.issuer.trim().is_empty() {
        return Err("capability_issuer_required");
    }
    if request.ttl_seconds <= 0 || request.ttl_seconds > COMMAND_CAPABILITY_MAX_TTL_SECONDS {
        return Err("invalid_capability_ttl");
    }
    let operations = expanded(&request.requested);
    if operations.is_empty() {
        return Err("capability_operations_required");
    }
    let supported: BTreeSet<&str> = request
        .supported_operations
        .iter()
        .map(String::as_str)
        .collect();
    for operation in &operations {
        // The exact-review grant is issued by the review path for itself and
        // is deliberately unclassified, so no capability may name it. An
        // operation this installation cannot execute, or one no local
        // side-effect class covers, is refused here rather than signed into a
        // grant the verifier would project away.
        if operation == EXACT_CLOUD_REVIEW_OPERATION
            || !supported.contains(operation.as_str())
            || !command_operation_is_classified(operation)
        {
            return Err("unsupported_capability_operation");
        }
    }
    if operations
        .iter()
        .any(|operation| POLICY_MEMORY_COMMAND_OPERATIONS.contains(&operation.as_str()))
        && operations.len() != 1
    {
        return Err("policy_memory_capability_must_be_isolated");
    }
    Ok(operations.into_iter().collect())
}

/// The typed words as exact operations: the group name stands for its class,
/// a comma joins several in one word, and spacing and repeats fall away.
fn expanded(requested: &[String]) -> BTreeSet<String> {
    let mut operations = BTreeSet::new();
    for word in requested {
        for part in word.split(',') {
            let name = part.trim();
            if name.is_empty() {
                continue;
            }
            if name == READ_ONLY_COMMAND_OPERATION_GROUP {
                operations.extend(
                    READ_ONLY_COMMAND_OPERATIONS
                        .iter()
                        .map(|operation| (*operation).to_owned()),
                );
            } else {
                operations.insert(name.to_owned());
            }
        }
    }
    operations
}

#[cfg(test)]
#[path = "command_capability_issue_op_tests.rs"]
mod tests;
