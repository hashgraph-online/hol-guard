//! `PackageApprovalHash` — resident op owning the package approval identity,
//! the composed current policy action, and the approval-context artifact hash
//! that `local_supply_chain.py` used to compute in Python.
//!
//! The caller hydrates only facts it alone can read (the configuration fields
//! the policy view is built from, the Python-built execution context and the
//! extension-control digest).
//! The cached feed snapshot hash is still accepted but not bound, and the
//! matched advisory ids are not bound either: a saved approval outlives a feed
//! refresh that matches a new advisory. The advisory still reaches the user as
//! a finding, and a blocking verdict still blocks, because a saved approval
//! never lowers `block` or `sandbox-required`. The runtime reads the workspace
//! manifests itself, composes the action, builds the approval identity and
//! returns the token; callers never recompute any of it.

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

use crate::package_authority_op::request_digest;

fn invalid() -> String {
    "native_package_approval_hash_invalid".to_owned()
}

fn field<'a>(map: &'a Value, key: &str) -> &'a Value {
    map.get(key).unwrap_or(&Value::Null)
}

/// Where the request reached the op from, which decides whether it may carry a
/// resolved policy view of its own.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PolicySource {
    /// `evaluate_package_approval_hash`: bytes any client can put on the
    /// resident socket.
    Wire,
    /// `package_current_action_and_hash`: the resident calling itself, with a
    /// view it built in process.
    InProcess,
}

/// The marker a caller sends when it has no configuration to hydrate a view
/// from. It is the only `config_policy` a wire request may carry.
fn is_unavailable_marker(policy: &Map<String, Value>) -> bool {
    policy.len() == 1 && policy.get("available") == Some(&Value::Bool(false))
}

/// The policy view the composed action and the approval context are bound to.
///
/// A caller that holds the loaded configuration sends the fields and the view
/// is hydrated here, so the `package_script` action and the override folded
/// into the composed action are resolved by the runtime and never by the
/// caller. A wire caller with nothing to hydrate the view from sends
/// `{"available": false}` and nothing else: a resolved view on the wire would
/// put `effective_package_script_action` and `resolved_override` back in the
/// caller's hands, so it is refused. The relay is the one caller that still
/// sends a view, and it does so in process, from the harness view the
/// publisher bound rather than from a request.
fn resolve_config_policy(
    request: &PackageApprovalHashRequestV1,
    source: PolicySource,
) -> Result<Value, String> {
    let Some(facts) = request.config_facts.as_ref() else {
        let policy = request.config_policy.as_object().ok_or_else(invalid)?;
        if source == PolicySource::Wire && !is_unavailable_marker(policy) {
            return Err(invalid());
        }
        return Ok(request.config_policy.clone());
    };
    if !request.config_policy.is_null() {
        return Err(invalid());
    }
    let facts = facts.as_object().ok_or_else(invalid)?;
    let artifact = &request.artifact;
    let harness = field(artifact, "harness").as_str().ok_or_else(invalid)?;
    let artifact_id = field(artifact, "artifact_id")
        .as_str()
        .ok_or_else(invalid)?;
    // The configuration fields and the managed-policy pair the approval hash
    // binds arrive in one map, so it stands for both halves.
    crate::package_config_mirror::config_policy(
        facts,
        facts,
        &crate::package_config_mirror::ArtifactIdentity {
            artifact_id,
            publisher: field(artifact, "publisher").as_str(),
            harness,
        },
    )
    .ok_or_else(invalid)
}

/// `most_restrictive_guard_action(policy_action, additional?, config actions…)`.
fn compose_current_action(
    request: &PackageApprovalHashRequestV1,
    config_policy: &Value,
) -> GuardAction {
    let mut actions = vec![field(&request.evaluation, "policy_action").clone()];
    if let Some(additional) = request.additional_current_action.as_ref() {
        actions.push(additional.clone());
    }
    for key in ["effective_package_script_action", "resolved_override"] {
        let action = field(config_policy, key);
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

/// Cloud transport fallbacks say where the evidence came from, not what the
/// policy is. The action they produce is already in `decision` and
/// `policy_action`, so leaving them out keeps a timeout from voiding approvals.
const EVIDENCE_SOURCE_REASON_CODES: [&str; 5] = [
    "cloud_auth_error",
    "cloud_http_error",
    "cloud_invalid_response",
    "cloud_timeout",
    "cloud_validation_error",
];

/// Per-package fields that name the package or carry its verdict. Scores, fix
/// suggestions, reason text and the advisory and rule ids that matched are left
/// out: a feed refresh rewrites them without changing what is installed or what
/// Guard decided about it.
const PACKAGE_POLICY_KEYS: [&str; 13] = [
    "alias",
    "decision",
    "dependencyPath",
    "direct",
    "ecosystem",
    "name",
    "namespace",
    "packageManager",
    "requestedVersion",
    "resolvedVersion",
    "sourceIdentity",
    "sourceRepository",
    "sourceRevisionKind",
];

/// Sorted, deduplicated reason codes. Messages are presentation text and may
/// change between bundle refreshes without the verdict changing.
fn policy_reason_codes(reasons: &Value) -> Vec<String> {
    let mut codes = reasons
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[])
        .iter()
        .filter_map(|reason| reason.get("code").and_then(Value::as_str))
        .filter(|code| !EVIDENCE_SOURCE_REASON_CODES.contains(code))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    codes.sort();
    codes.dedup();
    codes
}

fn policy_packages(packages: &Value) -> Value {
    let Some(items) = packages.as_array() else {
        return packages.clone();
    };
    let project = |package: &Value| -> Value {
        let Some(map) = package.as_object() else {
            return package.clone();
        };
        let mut projected = Map::new();
        for key in PACKAGE_POLICY_KEYS {
            if let Some(value) = map.get(key) {
                projected.insert(key.to_owned(), value.clone());
            }
        }
        if let Some(reasons) = map.get("reasons") {
            projected.insert(
                "reason_codes".to_owned(),
                json!(policy_reason_codes(reasons)),
            );
        }
        Value::Object(projected)
    };
    Value::Array(items.iter().map(project).collect())
}

/// The policy half of the approval context. Bundle and feed revisions, the
/// matched rule and the matched advisories are left out on purpose: Guard
/// Cloud refreshes them hourly, and a refresh must not void a saved approval.
/// `matched_rule_id` and `matched_advisory_ids` keep fixed values so approvals
/// saved before they left the context, with no rule or advisory matched, keep
/// the same token.
fn policy_context(
    request: &PackageApprovalHashRequestV1,
    config_policy: &Value,
    current_action: GuardAction,
) -> Value {
    let evaluation = &request.evaluation;
    let mut feed = Map::new();
    for key in [
        "decision",
        "enforcement",
        "entitlement_state",
        "exception_id",
        "policy_action",
    ] {
        feed.insert(key.to_owned(), field(evaluation, key).clone());
    }
    feed.insert("matched_rule_id".to_owned(), Value::Null);
    feed.insert(
        "packages".to_owned(),
        policy_packages(field(evaluation, "packages")),
    );
    feed.insert(
        "reason_codes".to_owned(),
        json!(policy_reason_codes(field(evaluation, "reasons"))),
    );
    feed.insert("matched_advisory_ids".to_owned(), json!([]));
    json!({
        "configuration": config_policy,
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
    config_policy: &Value,
    current_action: GuardAction,
) -> Result<String, String> {
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
    let policy = policy_context(request, config_policy, current_action);

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

/// The composed action and approval-context token in process, for the resident
/// itself rather than a request to it (`package_current_action_and_hash`,
/// `local_supply_chain.py:1014`). The request fields the byte path validates
/// around — the schema, the request id and the response digest — belong to that
/// path; the fields this reads are validated the same way.
pub(crate) fn package_current_action_and_hash(
    request: &PackageApprovalHashRequestV1,
) -> Result<(GuardAction, String), String> {
    if !request.evaluation.is_object() || !request.artifact.is_object() {
        return Err(invalid());
    }
    let config_policy = resolve_config_policy(request, PolicySource::InProcess)?;
    let current_action = compose_current_action(request, &config_policy);
    let artifact_hash = artifact_hash(request, &config_policy, current_action)?;
    Ok((current_action, artifact_hash))
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
    {
        return Err(invalid());
    }
    let config_policy = resolve_config_policy(request, PolicySource::Wire)?;
    let current_action = compose_current_action(request, &config_policy);
    let mut payload = Map::new();
    payload.insert("current_action".to_owned(), json!(current_action.as_str()));
    match request.kind.as_str() {
        "current_action" => {}
        "artifact_hash" => {
            payload.insert(
                "artifact_hash".to_owned(),
                Value::String(artifact_hash(request, &config_policy, current_action)?),
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
