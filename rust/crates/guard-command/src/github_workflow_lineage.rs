//! Rust port of `runtime/github_workflow_runtime.py::_validated_lineage` — the
//! decision that a persisted approval request, the Guard operation it resolved
//! and that operation's session really are one unbroken workflow lineage.
//!
//! Every caller of the Python function used its result to issue, claim or
//! preflight a workflow capability, so this is authority: it decides whether a
//! retry may reuse an earlier allow. The host reads the three rows out of the
//! store and ships them; nothing here touches the store, and nothing in Python
//! re-derives the verdict.
//!
//! The checks run in the Python order so a malformed lineage fails on the same
//! condition it used to, and each one carries the Python `ValueError` message
//! verbatim so the parity tests can name the condition they exercise. The op
//! collapses every one of them to "no lineage" on the wire: the host's only
//! use for the verdict is to refuse the retry, and the messages quote
//! workspace paths and identifiers that have no business crossing it.
//!
//! Resolving the workspace is the one deliberate difference. Python called
//! `Path.resolve()`, which resolves as far as it can and invents the rest;
//! `resolve_workspace` is strict, so a workspace that no longer exists is a
//! mismatch rather than a digest computed over a path nobody can open. Both
//! reject the request — the binding digest was taken over a workspace that
//! existed when the record was built — but the strict form cannot be talked
//! into hashing a path that was never on disk.

use serde_json::Value;

use crate::github_workflow_approval_record::GitHubWorkflowApprovalRecord;
use crate::github_workflow_descriptor::framed_digest;

/// The three `hook_event_name` spellings the harnesses send for a pre-tool
/// event (`_validated_lineage` :238-242).
const HOOK_EVENT_NAMES: &[&str] = &["PreToolUse", "beforeShellExecution", "preToolUse"];

/// The operation states a resolved workflow approval may be read back in
/// (:216-220).
const OPERATION_STATES: &[&str] = &["waiting_on_approval", "completed", "resumed"];

/// The identities a validated lineage yields. The host needs nothing else from
/// the operation or the session rows, so they stay on this side of the wire.
///
/// `capability_id` and `nonce` are derived here rather than by the host because
/// they name the capability the lineage authorizes: the id is what the host
/// looks up, issues and claims under, and the nonce binds the issued claim to
/// this one approval request. Deriving them anywhere else would let a second
/// implementation decide which capability an approval stands for.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedWorkflowLineage {
    pub request_id: String,
    pub operation_id: String,
    pub session_id: String,
    pub record: GitHubWorkflowApprovalRecord,
    pub capability_id: String,
    pub nonce: String,
}

/// `_validated_lineage` (:203). The two closures carry the filesystem work the
/// decision needs and nothing else: `resolve_workspace` is a strict
/// canonicalization of the operation's workspace, and `command_matches_record`
/// re-derives the persisted command against the record, which has to resolve
/// the executable on `PATH`.
pub fn validated_workflow_lineage(
    approval_request: &Value,
    operation: &Value,
    session: &Value,
    resolve_workspace: &dyn Fn(&str) -> Option<String>,
    command_matches_record: &dyn Fn(&str, &GitHubWorkflowApprovalRecord) -> bool,
) -> Result<ValidatedWorkflowLineage, String> {
    let request_id = required_string(approval_request, "request_id")?;
    let record = approval_record_from_approval_request(approval_request)
        .ok_or_else(|| "missing GitHub workflow approval record".to_string())?;

    let operation_request_ids = operation
        .get("approval_request_ids")
        .and_then(Value::as_array)
        .ok_or_else(|| "invalid Guard operation approval linkage".to_string())?;
    let linked = operation_request_ids
        .iter()
        .filter(|item| item.as_str() == Some(request_id.as_str()))
        .count();
    if linked != 1 {
        return Err("invalid Guard operation approval linkage".to_string());
    }

    let operation_state = operation.get("status").and_then(Value::as_str);
    if operation.get("operation_type").and_then(Value::as_str) != Some("tool_call")
        || !operation_state.is_some_and(|state| OPERATION_STATES.contains(&state))
    {
        return Err("invalid Guard workflow operation state".to_string());
    }

    let session_id = required_string(operation, "session_id")?;
    if required_string(session, "session_id")? != session_id {
        return Err("missing Guard session".to_string());
    }
    let capabilities = session.get("capabilities").and_then(Value::as_array);
    let resolves_approvals = capabilities.is_some_and(|items| {
        items
            .iter()
            .any(|item| item.as_str() == Some("approval-resolution"))
    });
    if session.get("surface").and_then(Value::as_str) != Some("harness-adapter")
        || !resolves_approvals
    {
        return Err("invalid Guard workflow session".to_string());
    }

    let harness = required_string(approval_request, "harness")?;
    if required_string(operation, "harness")? != harness
        || required_string(session, "harness")? != harness
    {
        return Err("Guard operation harness mismatch".to_string());
    }

    let metadata = operation
        .get("metadata")
        .filter(|value| value.is_object())
        .ok_or_else(|| "missing Guard operation metadata".to_string())?;
    let hook_event = metadata.get("hook_event_name").and_then(Value::as_str);
    if !hook_event.is_some_and(|name| HOOK_EVENT_NAMES.contains(&name)) {
        return Err("invalid Guard workflow hook event".to_string());
    }

    let command_text = metadata
        .get("command_text")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| "Guard operation command mismatch".to_string())?;
    if !command_matches_record(command_text, &record) {
        return Err("Guard operation command mismatch".to_string());
    }

    let operation_workspace = required_string(metadata, "workspace")?;
    let session_workspace = required_string(session, "workspace")?;
    let resolved = resolve_workspace(&operation_workspace);
    let workspace_bound = resolved
        .as_deref()
        .and_then(|path| framed_digest("github-workspace", &Value::String(path.to_string())))
        .is_some_and(|digest| digest == record.binding.workspace_sha256);
    if operation_workspace != session_workspace || !workspace_bound {
        return Err("Guard operation workspace mismatch".to_string());
    }

    if approval_request
        .get("artifact_type")
        .and_then(Value::as_str)
        != Some("tool_action_request")
    {
        return Err("invalid GitHub workflow approval type".to_string());
    }

    let capability_id = capability_identity(&request_id)?;
    let nonce = request_digest("github-workflow-nonce", &request_id)?;

    Ok(ValidatedWorkflowLineage {
        request_id,
        operation_id: required_string(operation, "operation_id")?,
        session_id,
        record,
        capability_id,
        nonce,
    })
}

/// `_capability_id` (:241) — the `gwc-` prefix over the framed request digest.
fn capability_identity(request_id: &str) -> Result<String, String> {
    Ok(format!(
        "gwc-{}",
        request_digest("github-workflow-capability", request_id)?
    ))
}

/// `_digest` (:245) over a request id. The framing cannot fail for a string
/// payload, so the error is unreachable in practice; it is a value rather than
/// a panic because a lineage that cannot name its capability must yield none.
fn request_digest(purpose: &str, request_id: &str) -> Result<String, String> {
    framed_digest(purpose, &Value::String(request_id.to_string()))
        .ok_or_else(|| "invalid GitHub workflow capability identity".to_string())
}

/// `approval_record_from_approval_request` (:144): exactly one
/// `github_workflow_approval_record` evidence row, decoded strictly. More than
/// one row, or a row whose payload is not a mapping, is no record at all.
pub fn approval_record_from_approval_request(
    approval_request: &Value,
) -> Option<GitHubWorkflowApprovalRecord> {
    let evidence = approval_request.get("scanner_evidence")?.as_array()?;
    let mut found: Option<GitHubWorkflowApprovalRecord> = None;
    for item in evidence {
        if item.get("source").and_then(Value::as_str) != Some("github_workflow_approval_record") {
            continue;
        }
        let payload = item.get("record").filter(|value| value.is_object())?;
        if found.is_some() {
            return None;
        }
        found = Some(GitHubWorkflowApprovalRecord::decode(payload).ok()?);
    }
    found
}

/// `_required_string` (:287) — a present, non-empty string or its `missing
/// <key>` message.
fn required_string(payload: &Value, key: &str) -> Result<String, String> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| format!("missing {key}"))
}
