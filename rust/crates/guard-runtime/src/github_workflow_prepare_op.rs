//! `GithubWorkflowPrepare` — resident op that builds the GitHub workflow
//! approval record for one hook command (`describe`) and re-verifies a
//! persisted record against its command text (`verify`).
//!
//! Ports `runtime/github_workflow_context.py::build_github_workflow_descriptor`
//! and `github_workflow_runtime.py::_persisted_command_matches_record`. Any
//! context-collection failure is "no descriptor", never an op error.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

use guard_command::command_model::parse_shell_command;
use guard_command::github_workflow_approval_record::GitHubWorkflowApprovalRecord;
use guard_command::github_workflow_authorization::{
    github_repository_sha256, GitHubWorkflowBindingContext,
};
use guard_command::github_workflow_descriptor::{
    approval_record_from_operation, framed_digest, persisted_command_matches_record,
    repository_from_remote, review_thread_location, viewer_from_user_payload,
    workspace_files_digest, GITHUB_WORKFLOW_LOCATOR_QUERY,
};
use guard_command::github_workflow_operations::parse_github_workflow_operation;
use guard_contracts::{
    GithubWorkflowPrepareRequestV1, GithubWorkflowPrepareResultV1, WorkflowCapabilityRuleBinding,
    GITHUB_WORKFLOW_PREPARE_MAX_BYTES, GITHUB_WORKFLOW_PREPARE_REQUEST_SCHEMA,
    GITHUB_WORKFLOW_PREPARE_RESULT_SCHEMA,
};
use serde_json::{json, Value};

use crate::github_workflow_context_io::{
    canonical_path, file_sha256, resolve_executable, run_bounded, workspace_file_entries,
    REQUEST_BUDGET,
};
use crate::package_authority_op::request_digest_with_limit;

const MANIFEST_FILES: [&str; 2] = ["pyproject.toml", "package.json"];
const LOCKFILES: [&str; 3] = ["uv.lock", "bun.lock", "bun.lockb"];

enum Outcome {
    Describe(Option<(String, Value)>),
    Verify(bool),
}

pub(crate) fn evaluate_github_workflow_prepare_request(
    request: &GithubWorkflowPrepareRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, GITHUB_WORKFLOW_PREPARE_MAX_BYTES)
        .map_err(|_| "native_github_workflow_prepare_too_large".to_owned())?;
    let mut result = GithubWorkflowPrepareResultV1 {
        schema: GITHUB_WORKFLOW_PREPARE_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "ok".to_owned(),
        code: "ok".to_owned(),
        command_identity: None,
        record: None,
        verified: None,
    };
    match evaluate(request) {
        Ok(Outcome::Describe(Some((identity, record)))) => {
            result.command_identity = Some(identity);
            result.record = Some(record);
        }
        Ok(Outcome::Describe(None)) => "none".clone_into(&mut result.code),
        Ok(Outcome::Verify(verified)) => result.verified = Some(verified),
        Err(code) => {
            "error".clone_into(&mut result.status);
            result.code = code.to_owned();
        }
    }
    crate::encode_response(&result)
}

fn evaluate(request: &GithubWorkflowPrepareRequestV1) -> Result<Outcome, &'static str> {
    if request.schema != GITHUB_WORKFLOW_PREPARE_REQUEST_SCHEMA {
        return Err("native_github_workflow_prepare_schema_mismatch");
    }
    match request.mode.as_str() {
        "describe" => describe(request).map(Outcome::Describe),
        "verify" => verify(request).map(Outcome::Verify),
        _ => Err("native_github_workflow_prepare_mode_invalid"),
    }
}

fn parse(
    text: &str,
    home: Option<&Path>,
    cwd: Option<&Path>,
) -> Option<guard_command::command_model::CanonicalCommand> {
    if text.trim().is_empty() {
        return None;
    }
    Some(parse_shell_command(
        text,
        cwd,
        home,
        "posix",
        "shell_string",
        "guard-shell",
        true,
    ))
}

fn describe(
    request: &GithubWorkflowPrepareRequestV1,
) -> Result<Option<(String, Value)>, &'static str> {
    const INVALID: &str = "native_github_workflow_prepare_invalid";
    let workspace = request.workspace.as_deref().ok_or(INVALID)?;
    let config_path = request.config_path.as_deref().ok_or(INVALID)?;
    let configuration = request.configuration.as_ref().ok_or(INVALID)?;
    let sandbox = request.sandbox.as_ref().ok_or(INVALID)?;
    let environment = request.environment.as_ref().ok_or(INVALID)?;
    let policy_version = request.policy_version.as_deref().ok_or(INVALID)?;
    Ok(collect_descriptor(
        &request.command_text,
        Path::new(workspace),
        config_path,
        configuration,
        sandbox,
        environment,
        policy_version,
    ))
}

#[allow(clippy::too_many_arguments)]
fn collect_descriptor(
    command_text: &str,
    workspace: &Path,
    config_path: &str,
    configuration: &Value,
    sandbox: &Value,
    environment: &BTreeMap<String, String>,
    policy_version: &str,
) -> Option<(String, Value)> {
    let deadline = Instant::now() + REQUEST_BUDGET;
    let root = canonical_path(workspace)?;
    let root_text = root.to_str()?;
    let path_value = environment.get("PATH").map(String::as_str);
    let gh_path = resolve_executable("gh", path_value)?;
    let gh_text = gh_path.to_str()?.to_owned();
    let repository = workspace_repository(&root, environment, path_value, deadline)?;
    let home = environment.get("HOME").map(Path::new);
    let command = parse(command_text, home, Some(&root))?;
    let mut operation = parse_github_workflow_operation(&command, Some(&repository), &gh_text);
    let candidate = operation
        .clone()
        .or_else(|| parse_github_workflow_operation(&command, Some("guard/locator"), &gh_text));
    let viewer =
        if let Some(candidate) = candidate.filter(|c| c.resource_type == "github-review-thread") {
            let arguments = vec![
                gh_text.clone(),
                "api".to_owned(),
                "graphql".to_owned(),
                "-f".to_owned(),
                format!("query={GITHUB_WORKFLOW_LOCATOR_QUERY}"),
                "-f".to_owned(),
                format!("threadId={}", candidate.resource_id),
            ];
            let payload = parse_json(&run_bounded(&arguments, &root, environment, deadline)?)?;
            let (located, viewer) =
                review_thread_location(&payload, &candidate.resource_id, &repository)?;
            operation = parse_github_workflow_operation(&command, Some(&located), &gh_text);
            viewer
        } else {
            operation.as_ref()?;
            let arguments = vec![gh_text.clone(), "api".to_owned(), "user".to_owned()];
            viewer_from_user_payload(&parse_json(&run_bounded(
                &arguments,
                &root,
                environment,
                deadline,
            )?)?)?
        };
    let operation = operation?;
    if operation.repository != repository || viewer.is_empty() {
        return None;
    }
    let viewer_sha256 = framed_digest(
        "github-viewer",
        &Value::String(caseless::default_case_fold_str(&viewer)),
    )?;
    let context = GitHubWorkflowBindingContext {
        repository_sha256: github_repository_sha256(&repository).ok()?,
        workspace_sha256: framed_digest("github-workspace", &json!(root_text))?,
        executable_sha256: file_sha256(&gh_path)?,
        cwd_sha256: framed_digest("github-cwd", &json!(root_text))?,
        environment_sha256: framed_digest(
            "github-environment",
            &json!({"environment": environment, "viewer_sha256": viewer_sha256}),
        )?,
        configuration_sha256: framed_digest(
            "github-configuration",
            &json!({"config_path": config_path, "effective": configuration}),
        )?,
        manifest_sha256: workspace_files_digest(&workspace_file_entries(&root, &MANIFEST_FILES)?)?,
        lockfile_sha256: workspace_files_digest(&workspace_file_entries(&root, &LOCKFILES)?)?,
        sandbox_sha256: framed_digest("github-sandbox", sandbox)?,
        policy_id: "guard.command-policy".to_owned(),
        policy_version: policy_version.to_owned(),
        effect_id: "github.maintain-remote".to_owned(),
        effect_version: "effect.v1".to_owned(),
        decision_id: "github.workflow-authorized".to_owned(),
        decision_version: "decision.v1".to_owned(),
        rules: vec![WorkflowCapabilityRuleBinding {
            rule_id: "github.maintain-remote".to_owned(),
            rule_version: "rule.v1".to_owned(),
        }],
    };
    let record = approval_record_from_operation(&operation, &context).ok()?;
    Some((operation.command_identity, record.to_value()))
}

fn parse_json(bytes: &[u8]) -> Option<Value> {
    crate::strict_json::parse(bytes).ok()
}

fn workspace_repository(
    root: &Path,
    environment: &BTreeMap<String, String>,
    path_value: Option<&str>,
    deadline: Instant,
) -> Option<String> {
    let git_path = resolve_executable("git", path_value)?;
    let arguments = vec![
        git_path.to_str()?.to_owned(),
        "-C".to_owned(),
        root.to_str()?.to_owned(),
        "config".to_owned(),
        "--get".to_owned(),
        "remote.origin.url".to_owned(),
    ];
    let raw = run_bounded(&arguments, root, environment, deadline)?;
    repository_from_remote(std::str::from_utf8(&raw).ok()?)
}

fn verify(request: &GithubWorkflowPrepareRequestV1) -> Result<bool, &'static str> {
    let record_value = request
        .record
        .as_ref()
        .ok_or("native_github_workflow_prepare_invalid")?;
    Ok(GitHubWorkflowApprovalRecord::decode(record_value)
        .is_ok_and(|record| persisted_matches(&request.command_text, &record)))
}

fn persisted_matches(command_text: &str, record: &GitHubWorkflowApprovalRecord) -> bool {
    let Some(command) = parse(command_text, None, None) else {
        return false;
    };
    if command.segments.len() != 1 {
        return false;
    }
    let Some(executable) = command.segments[0]
        .executable
        .as_deref()
        .filter(|text| !text.is_empty())
    else {
        return false;
    };
    let path = Path::new(executable);
    if !path.is_absolute() || canonical_path(path).as_deref() != Some(path) {
        return false;
    }
    if !crate::github_workflow_context_io::is_executable_file(path)
        || file_sha256(path).as_deref() != Some(record.binding.executable_sha256.as_str())
    {
        return false;
    }
    persisted_command_matches_record(&command, executable, record)
}

#[cfg(test)]
#[path = "github_workflow_prepare_op_tests.rs"]
mod tests;

#[cfg(all(test, unix))]
#[path = "github_workflow_prepare_op_stub_tests.rs"]
mod stub_tests;
