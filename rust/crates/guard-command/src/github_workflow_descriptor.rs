//! Pure half of the GitHub workflow descriptor: everything
//! `runtime/github_workflow_context.py` and `github_workflow_approval_record.py`
//! derived from already-collected inputs. The resident op owns the live
//! `git`/`gh` subprocess and filesystem collection and feeds these helpers.

use std::sync::OnceLock;

use guard_contracts::{canonical_framed_payload, WorkflowCapabilityBinding};
use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::command_model::CanonicalCommand;
use crate::github_workflow_approval_record::{
    GitHubWorkflowApprovalRecord, GITHUB_WORKFLOW_APPROVAL_RECORD_SCHEMA,
};
use crate::github_workflow_authorization::{
    build_github_workflow_binding, GitHubWorkflowBindingContext,
};
use crate::github_workflow_operations::{parse_github_workflow_operation, GitHubWorkflowOperation};

/// Parser-only repository for review-thread GraphQL commands, which carry no
/// repository. Never accepted as repository authority.
const GRAPHQL_REPOSITORY_PARSE_PLACEHOLDER: &str = "guard/locator";

/// `GraphQL` locator query the resident sends with `gh api graphql`.
pub const GITHUB_WORKFLOW_LOCATOR_QUERY: &str = "query($threadId:ID!){viewer{login}node(id:$threadId){__typename id ... on PullRequestReviewThread{pullRequest{number repository{nameWithOwner}}}}}";

/// `_digest` — sha256 hex of the canonical framed payload.
pub fn framed_digest(purpose: &str, payload: &Value) -> Option<String> {
    let framed = canonical_framed_payload(purpose, payload).ok()?;
    Some(hex::encode(Sha256::digest(&framed)))
}

fn https_remote() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^https://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$").expect("https remote")
    })
}

fn ssh_remote() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(?:ssh://git@github\.com/|git@github\.com:)([^/]+)/([^/]+?)(?:\.git)?$")
            .expect("ssh remote")
    })
}

/// `_workspace_repository` parse leg: `owner/repo` casefolded, or `None` when
/// the remote is not a github.com HTTPS/SSH URL.
pub fn repository_from_remote(raw: &str) -> Option<String> {
    let remote = raw.trim();
    let captures = https_remote()
        .captures(remote)
        .or_else(|| ssh_remote().captures(remote))?;
    let joined = format!("{}/{}", &captures[1], &captures[2]);
    Some(caseless::default_case_fold_str(&joined))
}

fn non_empty_string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key)?.as_str().filter(|text| !text.is_empty())
}

/// `_github_viewer` payload check: a JSON object with a non-empty `login`.
pub fn viewer_from_user_payload(payload: &Value) -> Option<String> {
    payload.as_object()?;
    non_empty_string(payload, "login").map(str::to_owned)
}

fn has_exact_keys(value: &Value, keys: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|map| map.len() == keys.len() && keys.iter().all(|key| map.contains_key(*key)))
}

/// Python `isinstance(value, int)`: integer JSON numbers and booleans.
fn python_int(value: &Value) -> bool {
    value.is_boolean() || value.as_number().is_some_and(|n| n.is_i64() || n.is_u64())
}

/// `_locate_review_thread` payload check -> `(repository, viewer login)`.
pub fn review_thread_location(
    payload: &Value,
    thread_id: &str,
    expected_repository: &str,
) -> Option<(String, String)> {
    if !has_exact_keys(payload, &["data"]) {
        return None;
    }
    let data = payload.get("data")?;
    if !has_exact_keys(data, &["node", "viewer"]) {
        return None;
    }
    let node = data.get("node")?;
    let viewer = data.get("viewer")?;
    if !has_exact_keys(node, &["__typename", "id", "pullRequest"])
        || node.get("__typename").and_then(Value::as_str) != Some("PullRequestReviewThread")
        || node.get("id").and_then(Value::as_str) != Some(thread_id)
    {
        return None;
    }
    let pull_request = node.get("pullRequest")?;
    if !has_exact_keys(pull_request, &["number", "repository"])
        || !python_int(pull_request.get("number")?)
    {
        return None;
    }
    let repository_payload = pull_request.get("repository")?;
    if !has_exact_keys(repository_payload, &["nameWithOwner"]) {
        return None;
    }
    let repository =
        caseless::default_case_fold_str(non_empty_string(repository_payload, "nameWithOwner")?);
    if repository != expected_repository || !viewer.is_object() {
        return None;
    }
    let login = non_empty_string(viewer, "login")?.to_owned();
    Some((repository, login))
}

/// `_workspace_files_sha256` final step over `(name, content sha256)` entries.
pub fn workspace_files_digest(entries: &[(String, String)]) -> Option<String> {
    let payload: Vec<Value> = entries
        .iter()
        .map(|(name, sha256)| json!({"name": name, "sha256": sha256}))
        .collect();
    framed_digest("github-workspace-files", &Value::Array(payload))
}

/// `GitHubWorkflowApprovalRecord.from_descriptor`.
pub fn approval_record_from_operation(
    operation: &GitHubWorkflowOperation,
    context: &GitHubWorkflowBindingContext,
) -> Result<GitHubWorkflowApprovalRecord, String> {
    let digest = |purpose: &str, text: &str| {
        framed_digest(purpose, &Value::String(text.to_owned()))
            .ok_or_else(|| "capability_canonical_json_failed".to_owned())
    };
    let binding: WorkflowCapabilityBinding =
        build_github_workflow_binding(operation, context).map_err(|error| error.to_string())?;
    let record = GitHubWorkflowApprovalRecord {
        schema_version: GITHUB_WORKFLOW_APPROVAL_RECORD_SCHEMA.to_owned(),
        operation_kind: operation.kind.as_str().to_owned(),
        resource_type: operation.resource_type.clone(),
        command_identity_sha256: digest(
            "github-workflow-command-identity",
            &operation.command_identity,
        )?,
        operation_digest_sha256: digest(
            "github-workflow-operation-digest",
            &operation.operation_digest,
        )?,
        binding,
    };
    record.validate()?;
    Ok(record)
}

/// `_persisted_command_matches_record` after the executable identity checks:
/// re-derive the operation from the persisted command text and compare it to
/// the signed record. Review-thread GraphQL commands carry no repository, so a
/// parser-only placeholder recovers their kind and node id.
pub fn persisted_command_matches_record(
    command: &CanonicalCommand,
    executable: &str,
    record: &GitHubWorkflowApprovalRecord,
) -> bool {
    let candidate = parse_github_workflow_operation(command, None, executable).or_else(|| {
        let placeholder = parse_github_workflow_operation(
            command,
            Some(GRAPHQL_REPOSITORY_PARSE_PLACEHOLDER),
            executable,
        )?;
        (placeholder.resource_type == "github-review-thread").then_some(placeholder)
    });
    let Some(candidate) = candidate else {
        return false;
    };
    let resource = framed_digest(
        "github-workflow-resource",
        &Value::String(candidate.resource_id.clone()),
    );
    let identity = framed_digest(
        "github-workflow-command-identity",
        &Value::String(command.security_identity()),
    );
    candidate.kind.as_str() == record.operation_kind
        && candidate.resource_type == record.resource_type
        && resource.as_deref() == Some(record.binding.resource_sha256.as_str())
        && identity.as_deref() == Some(record.command_identity_sha256.as_str())
}
