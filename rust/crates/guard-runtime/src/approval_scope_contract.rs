//! Action-aware approval scope contract of one pending request.
//!
//! Reusable allow scopes are exposed only when Guard can persist an
//! action-bound selector. A wider scope changes where that same action may be
//! reused; it never turns into blanket permission for unrelated actions.

use guard_command::github_workflow_approval_record::GitHubWorkflowApprovalRecord;
use guard_command::package_execution_context::package_execution_context_from_scanner_evidence;
use guard_contracts::ApprovalScopeItemV1;
use serde_json::{Map, Value};

use crate::approval_scope_material::scope_contract_digest;
use crate::context_digest::parse_context_token;
use crate::guard_store_json::py_strip;
use crate::local_mcp_grant_identity::composio_requires_action_review;

const SCOPED_APPROVAL_FAMILIES: [&str; 8] = [
    "file-read",
    "mcp",
    "mcp-tool",
    "package-request",
    "prompt",
    "prompt-env-read",
    "prompt-file",
    "tool-action",
];
const GUARD_CONTROL_ACTION_TYPES: [&str; 4] = [
    "guard_control",
    "guard-control",
    "guard_control_operation",
    "guard-control-operation",
];
const ONCE_ONLY_REASONS: [&str; 11] = [
    "no_command_identity",
    "mutable_launcher",
    "compound_command",
    "guard_control",
    "package_action",
    "non_overridable",
    "unproven_launch",
    "sensitive_path",
    "broad_scope",
    "destructive_command",
    "git_helper_config",
];
const NATIVE_REVIEW_BINDING_PREFIX: &str = "native-review-v4:";
const GITHUB_WORKFLOW_RECORD_SOURCE: &str = "github_workflow_approval_record";

/// The derived contract plus the exact-action token bound to the request.
pub(crate) struct ScopeContract {
    pub(crate) allow_scopes: Vec<&'static str>,
    pub(crate) block_scopes: Vec<&'static str>,
    pub(crate) recommended_allow: Option<&'static str>,
    pub(crate) recommended_block: Option<&'static str>,
    pub(crate) restrictions: Vec<&'static str>,
    pub(crate) digest: String,
    pub(crate) task_capability_eligible: bool,
    pub(crate) task_capability_reason_codes: Vec<&'static str>,
    pub(crate) exact_action_persistence_eligible: bool,
    pub(crate) once_only_reason: Option<String>,
    pub(crate) exact_context_token: Option<String>,
}

/// One request with its action envelope resolved once.
pub(crate) struct View<'a> {
    pub(crate) item: &'a ApprovalScopeItemV1,
    pub(crate) envelope: Option<&'a Map<String, Value>>,
}

impl<'a> View<'a> {
    pub(crate) fn new(item: &'a ApprovalScopeItemV1) -> Self {
        Self {
            item,
            envelope: item
                .action_envelope_json
                .as_ref()
                .and_then(Value::as_object),
        }
    }
}

/// `_string_or_none`: the original text when it is not blank.
pub(crate) fn text(value: Option<&Value>) -> Option<&str> {
    let text = value?.as_str()?;
    (!py_strip(text).is_empty()).then_some(text)
}

fn envelope_text<'a>(view: &View<'a>, key: &str) -> Option<&'a str> {
    text(view.envelope.and_then(|envelope| envelope.get(key)))
}

pub(crate) fn contract(view: &View<'_>) -> ScopeContract {
    let item = view.item;
    let artifact_available = text(item.artifact_id.as_ref()).is_some();
    let artifact_scopes: Vec<&'static str> = if artifact_available {
        vec!["artifact"]
    } else {
        Vec::new()
    };
    let non_overridable = allow_is_non_overridable(view);
    let unverified = unverified_provider_execution(view);
    let allow_scopes = if non_overridable {
        Vec::new()
    } else {
        reusable_allow_scopes(view, &artifact_scopes, unverified)
    };
    let mut block_scopes = artifact_scopes.clone();
    let trusted_family = request_scoped_family_key(view);
    let task_capability_eligible = github_workflow_task_capability_eligible(view);
    let persistence_eligible = exact_action_allow_persistence_eligible(view);
    let once_only_reason = if persistence_eligible {
        None
    } else {
        exact_action_once_only_reason(view)
    };
    let task_capability_reason_codes = if task_capability_eligible {
        vec!["exact_github_workflow_record"]
    } else {
        vec!["task_capability_not_enabled"]
    };
    if trusted_family.is_some() {
        if item.workspace_target.is_some() {
            block_scopes.push("workspace");
        }
        if text(item.publisher.as_ref()).is_some() {
            block_scopes.push("publisher");
        }
        block_scopes.extend(["harness", "global"]);
    }
    let mut restrictions = vec!["reusable_allow_is_action_bound"];
    if native_retry_cannot_reuse_approval(view) {
        restrictions.push("retry_cannot_reuse_approval");
    }
    if unverified {
        restrictions.push("provider_account_unverified_once_only");
    }
    restrictions.push(if task_capability_eligible {
        "task_capability_exact_operation_only"
    } else {
        "task_capability_not_enabled"
    });
    if non_overridable {
        restrictions.push("current_action_not_overridable");
    }
    if allow_scopes.contains(&"workspace") {
        restrictions.push("workspace_allow_bound_to_project_and_action");
    }
    if allow_scopes.contains(&"harness") || allow_scopes.contains(&"global") {
        restrictions.push("broad_allow_bound_to_exact_action");
    }
    if trusted_family.is_none() {
        restrictions.push("broad_deny_requires_trusted_selector");
    }
    let digest = scope_contract_digest(
        view,
        &allow_scopes,
        &block_scopes,
        &restrictions,
        task_capability_eligible,
        &task_capability_reason_codes,
        persistence_eligible,
    );
    ScopeContract {
        recommended_allow: if allow_scopes.contains(&"workspace") {
            Some("workspace")
        } else if allow_scopes.contains(&"artifact") {
            Some("artifact")
        } else {
            None
        },
        recommended_block: block_scopes.contains(&"artifact").then_some("artifact"),
        allow_scopes,
        block_scopes,
        restrictions,
        digest,
        task_capability_eligible,
        task_capability_reason_codes,
        exact_action_persistence_eligible: persistence_eligible,
        once_only_reason,
        exact_context_token: tool_call_exact_context_token(view),
    }
}

fn reusable_allow_scopes(
    view: &View<'_>,
    artifact_scopes: &[&'static str],
    unverified: bool,
) -> Vec<&'static str> {
    let item = view.item;
    if unverified || artifact_scopes.is_empty() || request_scoped_family_key(view).is_none() {
        return artifact_scopes.to_vec();
    }
    match text(item.artifact_hash.as_ref()) {
        None | Some("unknown") => return artifact_scopes.to_vec(),
        Some(_) => {}
    }
    let mut scopes = artifact_scopes.to_vec();
    let artifact_type = text(item.artifact_type.as_ref());
    let workspace = item.workspace_target.is_some();
    if workspace
        && matches!(
            artifact_type,
            Some("file_read_request" | "prompt_request" | "tool_action_request")
        )
    {
        scopes.push("workspace");
    } else if workspace && artifact_type == Some("package_request") {
        let evidence = item.scanner_evidence.clone().unwrap_or(Value::Null);
        if package_execution_context_from_scanner_evidence(&evidence)
            .is_some_and(|context| context.portable)
        {
            scopes.push("workspace");
        }
    }
    if artifact_type == Some("tool_action_request") && tool_action_has_exact_context(view) {
        scopes.extend(["harness", "global"]);
    }
    scopes
}

pub(crate) fn unverified_provider_execution(view: &View<'_>) -> bool {
    let item = view.item;
    if !matches!(
        item.artifact_type.as_ref().and_then(Value::as_str),
        Some("tool_call" | "tool_action_request")
    ) {
        return false;
    }
    let mut labels: Vec<Option<&Value>> = vec![item.artifact_name.as_ref()];
    if let Some(envelope) = view.envelope {
        labels.extend(["tool_name", "mcp_tool"].map(|key| envelope.get(key)));
    }
    if labels.iter().any(|label| {
        label
            .and_then(Value::as_str)
            .is_some_and(composio_requires_action_review)
    }) {
        return true;
    }
    item.raw_command_text
        .as_ref()
        .and_then(Value::as_str)
        .and_then(|raw| raw.strip_prefix("tool:"))
        .is_some_and(composio_requires_action_review)
}

fn tool_action_has_exact_context(view: &View<'_>) -> bool {
    text(view.item.raw_command_text.as_ref()).is_some()
        || envelope_text(view, "raw_command_text").is_some()
        || envelope_text(view, "command").is_some()
}

pub(crate) fn allow_is_non_overridable(view: &View<'_>) -> bool {
    if !matches!(
        text(view.item.policy_action.as_ref()),
        Some("require-reapproval" | "review")
    ) {
        return true;
    }
    envelope_text(view, "action_type")
        .is_some_and(|action_type| GUARD_CONTROL_ACTION_TYPES.contains(&action_type))
}

fn native_retry_cannot_reuse_approval(view: &View<'_>) -> bool {
    let Some(artifact_id) = view.item.artifact_id.as_ref().and_then(Value::as_str) else {
        return false;
    };
    if !artifact_id.contains(":native-pretool:") {
        return false;
    }
    !view
        .item
        .artifact_hash
        .as_ref()
        .and_then(Value::as_str)
        .is_some_and(|hash| hash.starts_with(NATIVE_REVIEW_BINDING_PREFIX))
}

fn is_context_token(value: &str) -> bool {
    parse_context_token(&Value::String(value.to_owned())).is_some()
}

fn tool_call_exact_context_token(view: &View<'_>) -> Option<String> {
    if let Some(hash) = text(view.item.artifact_hash.as_ref()) {
        if is_context_token(hash) {
            return Some(hash.to_owned());
        }
    }
    let token = envelope_text(view, "exact_context_token")?;
    is_context_token(token).then(|| token.to_owned())
}

fn exact_action_once_only_reason(view: &View<'_>) -> Option<String> {
    if unverified_provider_execution(view) {
        return Some("provider_unverified".to_owned());
    }
    if allow_is_non_overridable(view) {
        let action_type = view
            .envelope
            .and_then(|envelope| envelope.get("action_type"))
            .and_then(Value::as_str);
        return Some(
            if action_type.is_some_and(|value| GUARD_CONTROL_ACTION_TYPES.contains(&value)) {
                "guard_control"
            } else {
                "non_overridable"
            }
            .to_owned(),
        );
    }
    match text(view.item.artifact_type.as_ref()) {
        Some("package_request") => return Some("package_action".to_owned()),
        Some("tool_call") => {}
        _ => return None,
    }
    let stored = view
        .envelope
        .and_then(|envelope| envelope.get("once_only_reason"))
        .and_then(Value::as_str);
    if let Some(stored) = stored.filter(|value| ONCE_ONLY_REASONS.contains(value)) {
        return Some(stored.to_owned());
    }
    Some(
        if text(view.item.raw_command_text.as_ref()).is_some() {
            "unproven_launch"
        } else {
            "no_command_identity"
        }
        .to_owned(),
    )
}

pub(crate) fn exact_action_allow_persistence_eligible(view: &View<'_>) -> bool {
    if allow_is_non_overridable(view) || unverified_provider_execution(view) {
        return false;
    }
    let item = view.item;
    let artifact_id = text(item.artifact_id.as_ref());
    let artifact_hash = text(item.artifact_hash.as_ref());
    match text(item.artifact_type.as_ref()) {
        Some("package_request") => {
            artifact_id.is_some() && artifact_hash.is_some_and(|hash| hash != "unknown")
        }
        Some("tool_call") => {
            let tool_target = view
                .envelope
                .and_then(|envelope| envelope.get("exact_identity_kind"))
                .and_then(Value::as_str)
                == Some("tool-target");
            artifact_id.is_some()
                && tool_call_exact_context_token(view).is_some()
                && (text(item.raw_command_text.as_ref()).is_some() || tool_target)
        }
        Some("tool_action_request") => {
            let raw_command_text = text(item.raw_command_text.as_ref())
                .or_else(|| envelope_text(view, "raw_command_text"))
                .or_else(|| envelope_text(view, "command"));
            let context_bound = artifact_hash.is_some_and(is_context_token);
            let trusted_family =
                request_scoped_family_key(view).as_deref() == Some("family:tool-action");
            artifact_id.is_some()
                && artifact_hash.is_some_and(|hash| hash != "unknown")
                && text(item.action_identity.as_ref()).is_some()
                && raw_command_text.is_some()
                && (context_bound || trusted_family)
        }
        _ => false,
    }
}

fn artifact_family_key(artifact_id: &str) -> Option<String> {
    if py_strip(artifact_id).is_empty() {
        return None;
    }
    let family = if let Some(rest) = artifact_id.strip_prefix("family:") {
        py_strip(rest).to_lowercase()
    } else {
        let parts: Vec<&str> = artifact_id.split(':').collect();
        if parts.len() < 3 {
            return None;
        }
        py_strip(parts[2]).to_lowercase()
    };
    SCOPED_APPROVAL_FAMILIES
        .contains(&family.as_str())
        .then(|| format!("family:{family}"))
}

pub(crate) fn request_scoped_family_key(view: &View<'_>) -> Option<String> {
    let family_key = artifact_family_key(text(view.item.artifact_id.as_ref())?)?;
    let artifact_type = text(view.item.artifact_type.as_ref())?;
    let expected: &[&str] = match artifact_type {
        "file_read_request" => &["file-read"],
        "mcp_server" | "mcp_tool_call" => &["mcp", "mcp-tool"],
        "package_request" => &["package-request"],
        "prompt_request" => &["prompt", "prompt-env-read", "prompt-file"],
        "tool_action_request" => &["tool-action"],
        _ => return None,
    };
    let family = family_key.strip_prefix("family:").unwrap_or(&family_key);
    expected.contains(&family).then_some(family_key.clone())
}

/// Exactly one well-formed GitHub workflow approval record marks the request
/// as a task-capability candidate. Anything malformed is not eligible.
fn github_workflow_task_capability_eligible(view: &View<'_>) -> bool {
    let Some(Value::Array(evidence)) = view.item.scanner_evidence.as_ref() else {
        return false;
    };
    let mut records = Vec::new();
    for entry in evidence {
        let Some(entry) = entry.as_object() else {
            continue;
        };
        if entry.get("source").and_then(Value::as_str) != Some(GITHUB_WORKFLOW_RECORD_SOURCE) {
            continue;
        }
        match entry.get("record") {
            Some(record @ Value::Object(_)) => records.push(record),
            _ => return false,
        }
    }
    records.len() == 1 && GitHubWorkflowApprovalRecord::decode(records[0]).is_ok()
}
