//! `PackageApprovalHash` — resident op owning the package approval identity,
//! the composed current policy action, and the approval-context artifact hash
//! that `local_supply_chain.py` used to compute in Python.
//!
//! The caller hydrates only facts it alone can read (the bound `GuardConfig`
//! view, the Python-built execution context, the extension-control digest and
//! the cached feed snapshot hash). The runtime reads the advisory cache and the
//! workspace manifests itself, composes the action, builds the approval
//! identity and returns the token; callers never recompute any of it.

use guard_command::action_lattice::most_restrictive_guard_action;
use guard_command::effect_decision::GuardAction;
use guard_command::launch_identity::package_request_launch_identity_material;
use guard_command::local_supply_chain::stable_digest_hex;
use guard_command::package_approval::{package_approval_identity, PackageApprovalIdentityInput};
use guard_command::package_execution_context::{
    PackageExecutionContext, PackageExecutionContextComponent, PACKAGE_EXECUTION_CONTEXT_VERSION,
};
use guard_command::package_intent_common::resolve_path_within_workspace;
use guard_command::supply_chain_package_eval::LOCKFILE_PARSER_VERSION;
use guard_contracts::{
    ContextDigestComponentsV1, PackageApprovalHashRequestV1, SupplyChainEvalResultV1,
    PACKAGE_AUTHORITY_REQUEST_SCHEMA, PACKAGE_AUTHORITY_RESULT_SCHEMA,
};
use serde_json::{json, Map, Value};
use std::path::Path;

use crate::package_authority_op::{matched_advisory_ids, request_digest};

fn invalid() -> String {
    "native_package_approval_hash_invalid".to_owned()
}

fn field<'a>(map: &'a Value, key: &str) -> &'a Value {
    map.get(key).unwrap_or(&Value::Null)
}

/// `most_restrictive_guard_action(policy_action, additional?, config actions…)`.
fn compose_current_action(request: &PackageApprovalHashRequestV1) -> GuardAction {
    let mut actions = vec![field(&request.evaluation, "policy_action").clone()];
    if let Some(additional) = request.additional_current_action.as_ref() {
        actions.push(additional.clone());
    }
    for key in ["effective_package_script_action", "resolved_override"] {
        let action = field(&request.config_policy, key);
        if !action.is_null() {
            actions.push(action.clone());
        }
    }
    most_restrictive_guard_action(&actions, GuardAction::Block)
}

fn string_items(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn hash_existing_paths(workspace: &Path, relative_paths: &[String]) -> Vec<Value> {
    relative_paths
        .iter()
        .filter_map(|relative| {
            let resolved = resolve_path_within_workspace(workspace, relative)?;
            if !resolved.is_file() {
                return None;
            }
            let payload = std::fs::read(resolved).ok()?;
            Some(Value::String(stable_digest_hex(&payload)))
        })
        .collect()
}

fn parse_execution_context(value: Option<&Value>) -> Result<PackageExecutionContext, String> {
    let map = value.and_then(Value::as_object).ok_or_else(invalid)?;
    if map.get("version").and_then(Value::as_u64) != Some(PACKAGE_EXECUTION_CONTEXT_VERSION) {
        return Err(invalid());
    }
    let digest = map
        .get("digest")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?
        .to_owned();
    let components = map
        .get("components")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?
        .iter()
        .map(|item| {
            let name = item.get("name").and_then(Value::as_str)?;
            let digest = item.get("digest").and_then(Value::as_str)?;
            Some(PackageExecutionContextComponent {
                name: name.to_owned(),
                digest: digest.to_owned(),
            })
        })
        .collect::<Option<Vec<_>>>()
        .ok_or_else(invalid)?;
    Ok(PackageExecutionContext {
        digest,
        portable: true,
        components,
        non_portable_reason: None,
    })
}

fn policy_context(
    request: &PackageApprovalHashRequestV1,
    current_action: GuardAction,
    matched_ids: Vec<String>,
) -> Value {
    let evaluation = &request.evaluation;
    let mut feed = Map::new();
    for key in [
        "bundle_version",
        "decision",
        "enforcement",
        "entitlement_state",
        "exception_id",
        "matched_rule_id",
        "packages",
        "policy_action",
        "policy_version",
        "reasons",
    ] {
        feed.insert(key.to_owned(), field(evaluation, key).clone());
    }
    feed.insert(
        "feed_snapshot_hash".to_owned(),
        request
            .feed_snapshot_hash
            .clone()
            .map_or(Value::Null, Value::String),
    );
    feed.insert("matched_advisory_ids".to_owned(), json!(matched_ids));
    json!({
        "configuration": request.config_policy,
        "current_action": current_action.as_str(),
        "additional": request
            .additional_policy_context
            .clone()
            .unwrap_or_else(|| json!({"available": false})),
        "feed": Value::Object(feed),
        "version": 1,
    })
}

fn artifact_hash(
    request: &PackageApprovalHashRequestV1,
    current_action: GuardAction,
) -> Result<String, String> {
    let store_path = request.store_path.as_deref().ok_or_else(invalid)?;
    let workspace = request.workspace_dir.as_deref().ok_or_else(invalid)?;
    let extension_control_digest = request
        .extension_control_digest
        .clone()
        .ok_or_else(invalid)?;
    let sandbox_analysis = request.sandbox_analysis.clone().ok_or_else(invalid)?;
    let execution_context = parse_execution_context(request.execution_context.as_ref())?;
    let launch_identity = match request.launch_identity.as_ref() {
        None => None,
        Some(Value::Object(map)) => Some(map),
        Some(_) => return Err(invalid()),
    };
    let matched_ids = matched_advisory_ids(&request.artifact, store_path)?
        .into_iter()
        .collect::<Vec<_>>();
    let policy = policy_context(request, current_action, matched_ids);

    let artifact = &request.artifact;
    let metadata = artifact
        .get("metadata")
        .filter(|value| value.is_object())
        .cloned()
        .unwrap_or_else(|| json!({}));
    let approval_identity = package_approval_identity(&PackageApprovalIdentityInput {
        artifact_metadata: &metadata,
        evaluation: &request.evaluation,
        execution_context: &execution_context,
    });
    let component = |name: &str| -> Value {
        execution_context
            .components
            .iter()
            .rev()
            .find(|item| item.name == name)
            .map_or(Value::Null, |item| Value::String(item.digest.clone()))
    };
    let manifest_paths = string_items(field(&metadata, "manifest_paths"));
    let lockfile_paths = string_items(field(&metadata, "lockfile_paths"));
    let mut content = Map::new();
    if !manifest_paths.is_empty() || !lockfile_paths.is_empty() {
        let workspace = Path::new(workspace);
        content.insert("manifest_paths".to_owned(), json!(manifest_paths));
        content.insert("lockfile_paths".to_owned(), json!(lockfile_paths));
        content.insert(
            "manifest_hashes".to_owned(),
            Value::Array(hash_existing_paths(workspace, &manifest_paths)),
        );
        content.insert(
            "lockfile_hashes".to_owned(),
            Value::Array(hash_existing_paths(workspace, &lockfile_paths)),
        );
    }
    content.insert(
        "lockfile_parser_version".to_owned(),
        json!(LOCKFILE_PARSER_VERSION),
    );
    content.insert(
        "manifests_and_lockfiles".to_owned(),
        component("manifests_and_lockfiles"),
    );
    content.insert(
        "workspace_configuration".to_owned(),
        component("workspace_configuration"),
    );
    let identity = json!({
        "approval_identity": approval_identity,
        "artifact_id": field(artifact, "artifact_id"),
        "config_path": field(artifact, "config_path"),
        "exact_workspace": component("exact_workspace"),
        "package_manager_executable": component("package_manager_executable"),
        "package_launch_identity": Value::Object(package_request_launch_identity_material(launch_identity)),
        "publisher": field(artifact, "publisher"),
        "repository_identity": component("repository_identity"),
        "source_scope": field(artifact, "source_scope"),
        "workspace_identity": component("workspace_identity"),
    });
    let capabilities = json!({
        "environment_policy": component("environment_policy"),
        "lifecycle_hooks_overrides_and_patches": component("lifecycle_hooks_overrides_and_patches"),
        "registry_and_proxy_configuration": component("registry_and_proxy_configuration"),
    });
    let sandbox = json!({
        "analysis": sandbox_analysis,
        "required": current_action == GuardAction::SandboxRequired,
    });
    crate::context_digest::build_context_token(&ContextDigestComponentsV1 {
        identity,
        content: Value::Object(content),
        capabilities,
        policy,
        sandbox,
        extension_control_digest,
    })
    .map_err(|_| invalid())
}

pub(crate) fn evaluate_package_approval_hash(
    request: &PackageApprovalHashRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    if request.schema != PACKAGE_AUTHORITY_REQUEST_SCHEMA {
        return Err("native_package_approval_hash_schema_mismatch".to_owned());
    }
    if request.request_id.is_empty()
        || request.guard_home.is_empty()
        || !request.evaluation.is_object()
        || !request.artifact.is_object()
        || !request.config_policy.is_object()
    {
        return Err(invalid());
    }
    let current_action = compose_current_action(request);
    let mut payload = Map::new();
    payload.insert("current_action".to_owned(), json!(current_action.as_str()));
    match request.kind.as_str() {
        "current_action" => {}
        "artifact_hash" => {
            payload.insert(
                "artifact_hash".to_owned(),
                Value::String(artifact_hash(request, current_action)?),
            );
        }
        _ => return Err(invalid()),
    }
    crate::encode_response(&SupplyChainEvalResultV1 {
        schema: PACKAGE_AUTHORITY_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "ok".to_owned(),
        code: "ok".to_owned(),
        payload: Some(Value::Object(payload)),
    })
}

#[cfg(test)]
#[path = "package_approval_hash_op_tests.rs"]
mod tests;
