//! `ApprovalResolutionPlan` - resident op that decides what resolving one
//! approval request writes.
//!
//! Pure: derives the policy decision identity (including the runtime-exact and
//! browser keys), the persistence mode, the local-once fallback row and the
//! sibling-request selector from the narrowed request fields. The caller only
//! executes the returned plan against its store, so Python never recomputes a
//! key, scope or expiry.

use guard_contracts::{
    ApprovalResolutionPlanApprovalV1, ApprovalResolutionPlanBrowserIntentV1,
    ApprovalResolutionPlanEnvelopeV1, ApprovalResolutionPlanRequestV1,
    ApprovalResolutionPlanResultV1, APPROVAL_RESOLUTION_PLAN_MAX_BYTES,
    APPROVAL_RESOLUTION_PLAN_REQUEST_SCHEMA, APPROVAL_RESOLUTION_PLAN_RESULT_SCHEMA,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::approval_resolution_plan_token::is_valid_approval_context_token;
use crate::guard_store_json::{add_seconds_isoformat, dumps_sorted, py_strip};
use crate::package_authority_op::request_digest_with_limit;

const INVALID: &str = "native_approval_resolution_plan_invalid";
const RUNTIME_EXACT_PREFIX: &str = "runtime-exact:";
const LOCAL_SUPPLY_CHAIN_HARNESS: &str = "guard-cli";
/// `_APPROVAL_ONCE_POLICY_TTL`: 15 minutes.
const ONCE_TTL_MICROS: i64 = 15 * 60 * 1_000_000;

const APPROVAL_FAMILIES: [&str; 8] = [
    "file-read",
    "mcp",
    "mcp-tool",
    "package-request",
    "prompt",
    "prompt-env-read",
    "prompt-file",
    "tool-action",
];
const RUNTIME_EXACT_FAMILIES: [&str; 5] = [
    "file-read",
    "mcp-tool",
    "package-request",
    "prompt",
    "tool-action",
];
const WORKSPACE_SCOPED_TYPES: [&str; 4] = [
    "file_read_request",
    "package_request",
    "prompt_request",
    "tool_action_request",
];

pub(crate) fn evaluate_approval_resolution_plan_request(
    request: &ApprovalResolutionPlanRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, APPROVAL_RESOLUTION_PLAN_MAX_BYTES)
        .map_err(|_| "native_approval_resolution_plan_too_large".to_owned())?;
    let (status, code, payload) = match evaluate(request) {
        Ok(payload) => ("ok".to_owned(), "ok".to_owned(), Some(payload)),
        Err(code) => ("error".to_owned(), code, None),
    };
    crate::encode_response(&ApprovalResolutionPlanResultV1 {
        schema: APPROVAL_RESOLUTION_PLAN_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status,
        code,
        payload,
    })
}

/// `_string_or_none`: a non-empty string, else nothing.
fn text(value: &Option<String>) -> Option<&str> {
    value.as_deref().filter(|value| !value.is_empty())
}

fn sha256_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

/// `artifact_family_key` over the scoped approval families, as the family name.
fn family_name(artifact_id: &str) -> Option<String> {
    if py_strip(artifact_id).is_empty() {
        return None;
    }
    let family = if let Some(rest) = artifact_id.strip_prefix("family:") {
        let family = py_strip(rest).to_lowercase();
        if !APPROVAL_FAMILIES.contains(&family.as_str()) {
            return None;
        }
        // The family key is the id itself; its value is what follows `family:`.
        return Some(rest.to_owned());
    } else {
        let parts: Vec<&str> = artifact_id.split(':').collect();
        if parts.len() < 3 {
            return None;
        }
        py_strip(parts[2]).to_lowercase()
    };
    APPROVAL_FAMILIES
        .contains(&family.as_str())
        .then_some(family)
}

fn is_runtime_exact_family(artifact_id: &str) -> Option<String> {
    family_name(artifact_id).filter(|family| RUNTIME_EXACT_FAMILIES.contains(&family.as_str()))
}

/// `runtime_tool_action_policy_artifact_id`.
fn policy_artifact_id(artifact_id: Option<&str>) -> Option<String> {
    let id = artifact_id?;
    if py_strip(id).is_empty() {
        return None;
    }
    if is_runtime_exact_family(id).is_some() {
        return Some(id.to_owned());
    }
    Some(format!(
        "guard:runtime:tool-action:{}",
        sha256_hex(py_strip(id))
    ))
}

/// `_runtime_scoped_exact_match_key`.
fn runtime_exact_key(artifact_id: &str, context: Option<&str>) -> Option<String> {
    if py_strip(artifact_id).is_empty() || artifact_id.starts_with("family:") {
        return None;
    }
    is_runtime_exact_family(artifact_id)?;
    let digest = match context {
        None => sha256_hex(artifact_id),
        Some(context) => sha256_hex(&dumps_sorted(&json!({
            "artifact_id": artifact_id,
            "context": context,
            "version": 2,
        }))?),
    };
    Some(format!("{RUNTIME_EXACT_PREFIX}{digest}"))
}

/// `_global_runtime_scoped_exact_match_key`.
fn global_runtime_exact_key(artifact_id: &str, context: Option<&str>) -> Option<String> {
    let family = is_runtime_exact_family(artifact_id)?;
    runtime_exact_key(&format!("global:portable:{family}"), context)
}

fn wrapper_strings(chain: &[Option<String>]) -> Vec<Value> {
    chain
        .iter()
        .filter_map(|item| item.as_deref())
        .filter(|item| !item.is_empty())
        .map(|item| json!(item))
        .collect()
}

/// `runtime_tool_action_exact_match_context`.
fn exact_context(
    config_path: Option<&str>,
    source_scope: Option<&str>,
    raw_command_text: Option<&str>,
    wrapper_chain: Option<&[Option<String>]>,
    permission_mode: Option<&str>,
) -> Option<String> {
    let has_wrapper = wrapper_chain.is_some_and(|chain| !chain.is_empty());
    if config_path.is_none()
        && source_scope.is_none()
        && raw_command_text.is_none()
        && !has_wrapper
        && permission_mode.is_none()
    {
        return None;
    }
    let mut payload = Map::new();
    payload.insert("config_path".into(), json!(config_path));
    payload.insert("source_scope".into(), json!(source_scope));
    payload.insert("raw_command_text".into(), json!(raw_command_text));
    payload.insert(
        "wrapper_chain".into(),
        Value::Array(wrapper_chain.map(wrapper_strings).unwrap_or_default()),
    );
    payload.insert("permission_mode".into(), json!(permission_mode));
    dumps_sorted(&Value::Object(payload))
}

fn permission_mode(envelope: Option<&ApprovalResolutionPlanEnvelopeV1>) -> Option<&str> {
    let envelope = envelope?;
    text(&envelope.permission_mode).or_else(|| text(&envelope.permission_mode_camel))
}

/// `_workspace_policy_artifact_keys`.
fn workspace_artifact_keys(
    approval: &ApprovalResolutionPlanApprovalV1,
    scope: &str,
) -> (Option<String>, Option<String>) {
    let scoped_type = approval
        .artifact_type
        .as_deref()
        .is_some_and(|kind| WORKSPACE_SCOPED_TYPES.contains(&kind));
    if scope != "workspace" || !scoped_type {
        return (None, None);
    }
    let Some(artifact_id) = text(&approval.artifact_id) else {
        return (None, None);
    };
    (
        Some(artifact_id.to_owned()),
        text(&approval.artifact_hash).map(str::to_owned),
    )
}

/// `_artifact_scope_runtime_exact_match_key`.
fn artifact_scope_key(
    approval: &ApprovalResolutionPlanApprovalV1,
    scope: &str,
    include_envelope_command: bool,
) -> Option<String> {
    if scope != "artifact" || approval.artifact_type.as_deref() != Some("tool_action_request") {
        return None;
    }
    let request_artifact_id = text(&approval.artifact_id);
    let artifact_id = policy_artifact_id(request_artifact_id);
    let synthesized = artifact_id.as_deref() != request_artifact_id;
    if synthesized && !include_envelope_command {
        return None;
    }
    let mut raw = text(&approval.raw_command_text);
    let mut wrapper = approval.wrapper_chain.as_deref();
    if let Some(envelope) = &approval.envelope {
        raw = raw
            .or_else(|| text(&envelope.raw_command_text))
            .or_else(|| {
                include_envelope_command
                    .then(|| text(&envelope.command))
                    .flatten()
            });
        wrapper = wrapper.or(envelope.wrapper_chain.as_deref());
    }
    if synthesized && raw.is_none() {
        return None;
    }
    let context = exact_context(
        text(&approval.config_path),
        text(&approval.source_scope),
        raw,
        wrapper,
        permission_mode(approval.envelope.as_ref()),
    );
    runtime_exact_key(artifact_id.as_deref()?, context.as_deref())
}

/// `_broad_runtime_exact_match_key`.
fn broad_key(approval: &ApprovalResolutionPlanApprovalV1, scope: &str) -> Option<String> {
    if scope != "harness" && scope != "global" {
        return None;
    }
    let artifact_type = approval.artifact_type.as_deref()?;
    if !WORKSPACE_SCOPED_TYPES.contains(&artifact_type) {
        return None;
    }
    let artifact_id = text(&approval.artifact_id)?;
    if artifact_type != "tool_action_request" {
        return runtime_exact_key(artifact_id, None);
    }
    let mut raw = text(&approval.raw_command_text);
    let mut wrapper = approval.wrapper_chain.as_deref();
    if let Some(envelope) = &approval.envelope {
        raw = raw
            .or_else(|| text(&envelope.raw_command_text))
            .or_else(|| text(&envelope.command));
        wrapper = wrapper.or(envelope.wrapper_chain.as_deref());
    }
    let raw = raw?;
    // The exact context minus its project-location fields: the identical
    // executable action matches across workspaces.
    let portable = exact_context(
        None,
        None,
        Some(raw),
        wrapper,
        permission_mode(approval.envelope.as_ref()),
    );
    if scope == "global" {
        global_runtime_exact_key(artifact_id, portable.as_deref())
    } else {
        runtime_exact_key(artifact_id, portable.as_deref())
    }
}

/// `browser_mcp_exact_match_context`.
fn browser_context(intent: &ApprovalResolutionPlanBrowserIntentV1) -> Option<String> {
    if text(&intent.intent).is_none()
        && text(&intent.operation).is_none()
        && text(&intent.target_origin).is_none()
    {
        return None;
    }
    let mut flags: Vec<&str> = intent
        .sensitive_surface_flags
        .iter()
        .flatten()
        .map(String::as_str)
        .filter(|flag| !flag.is_empty())
        .collect();
    flags.sort_unstable();
    dumps_sorted(&json!({
        "intent": text(&intent.intent),
        "operation": text(&intent.operation),
        "target_origin": text(&intent.target_origin),
        "target_path_prefix": text(&intent.target_path_prefix),
        "profile_mode": text(&intent.profile_mode),
        "server_identity_hash": text(&intent.mcp_server_identity_hash),
        "tool_identity_hash": text(&intent.mcp_tool_identity_hash),
        "schema_hash": text(&intent.mcp_schema_hash),
        "sensitive_surface_flags": flags,
    }))
}

/// `_browser_mcp_exact_match_key`.
fn browser_key(approval: &ApprovalResolutionPlanApprovalV1, scope: &str) -> Option<String> {
    if scope != "artifact" || approval.artifact_type.as_deref() != Some("tool_call") {
        return None;
    }
    let intent = approval.browser_intent.as_ref()?;
    let artifact_id = text(&approval.artifact_id)?;
    let context = browser_context(intent)?;
    runtime_exact_key(artifact_id, Some(&context))
}

/// `_approval_policy_harness`.
fn policy_harness(approval: &ApprovalResolutionPlanApprovalV1) -> Result<String, String> {
    let local_package = approval.artifact_type.as_deref() == Some("package_request")
        && approval.artifact_id.as_deref().is_some_and(|id| {
            id.starts_with(&format!(
                "{LOCAL_SUPPLY_CHAIN_HARNESS}:project:package-request:"
            ))
        });
    if local_package {
        return Ok(LOCAL_SUPPLY_CHAIN_HARNESS.to_owned());
    }
    approval.harness.clone().ok_or_else(|| INVALID.to_owned())
}

/// `_approval_once_policy_expires_at`.
fn once_expires_at(resolved_at: &str) -> Result<String, String> {
    add_seconds_isoformat(resolved_at, ONCE_TTL_MICROS).ok_or_else(|| INVALID.to_owned())
}

fn evaluate(request: &ApprovalResolutionPlanRequestV1) -> Result<Value, String> {
    if request.schema != APPROVAL_RESOLUTION_PLAN_REQUEST_SCHEMA {
        return Err("native_approval_resolution_plan_schema_mismatch".to_owned());
    }
    let approval = &request.approval;
    let scope = request.scope.as_str();
    let allow = request.action == "allow";
    let (workspace_id, workspace_hash) = workspace_artifact_keys(approval, scope);
    let request_artifact_id = text(&approval.artifact_id).map(str::to_owned);
    let request_artifact_hash = text(&approval.artifact_hash).map(str::to_owned);
    let context_token = request_artifact_hash
        .clone()
        .filter(|hash| is_valid_approval_context_token(hash));
    let exact_context_allow = allow && context_token.is_some();
    let persist = request.persist_policy;

    let mut scoped_id = if matches!(scope, "artifact" | "harness" | "global") {
        request_artifact_id.clone()
    } else {
        workspace_id
    };
    let mut scoped_hash = if scope == "artifact" {
        request_artifact_hash.clone()
    } else {
        workspace_hash
    };
    if exact_context_allow {
        // The token already binds the exact request across every security
        // dimension; broad scopes stay match selectors and never discard it.
        scoped_hash = context_token.clone();
        if matches!(scope, "artifact" | "workspace" | "harness" | "global") {
            scoped_id = request_artifact_id.clone();
        }
    } else {
        if let Some(key) = artifact_scope_key(approval, scope, persist == Some(true)) {
            scoped_id = policy_artifact_id(request_artifact_id.as_deref());
            scoped_hash = Some(key);
        }
        if let Some(key) = broad_key(approval, scope) {
            scoped_hash = Some(key);
        }
        if let Some(key) = browser_key(approval, scope) {
            scoped_hash = Some(key);
        }
    }
    let mut native_once_hash: Option<String> = None;
    if persist == Some(true) && scope == "artifact" && context_token.is_none() {
        // A native review row keeps its per-call binding for once flows; a saved
        // decision keys on the stable exact-action token.
        if let Some(token) = text(&request.native_exact_token) {
            scoped_id = request_artifact_id.clone();
            scoped_hash = Some(token.to_owned());
            native_once_hash = request_artifact_hash.clone();
        }
    }
    if scope != "global" && approval.harness.is_none() {
        return Err(INVALID.to_owned());
    }
    let publisher = text(&approval.publisher).map(str::to_owned);
    let workspace = (scope == "workspace")
        .then(|| request.resolved_workspace.clone())
        .flatten();
    let decision_harness = if scope == "global" {
        "*".to_owned()
    } else {
        policy_harness(approval)?
    };
    let decision_action = if allow { "allow" } else { "block" };
    let decision_publisher = (scope == "publisher").then(|| publisher.clone()).flatten();
    let decision = json!({
        "harness": decision_harness,
        "scope": scope,
        "action": decision_action,
        "artifact_id": scoped_id,
        "artifact_hash": scoped_hash,
        "workspace": workspace,
        "publisher": decision_publisher,
    });
    let local_once = |hash: &Option<String>, expires_at: String| -> Result<Value, String> {
        Ok(json!({
            "harness": policy_harness(approval)?,
            "artifact_id": scoped_id,
            "artifact_hash": hash,
            "workspace": workspace,
            "publisher": decision_publisher,
            "action": decision_action,
            "expires_at": expires_at,
        }))
    };

    let persisted_rule = persist == Some(true) || (persist.is_none() && scope != "artifact");
    let mut persistence = "none";
    let mut once_expiry: Option<String> = None;
    let mut local_once_row = Value::Null;
    if persisted_rule {
        persistence = "persisted";
        if allow && request.requires_local_once {
            let hash = native_once_hash.clone().or_else(|| scoped_hash.clone());
            local_once_row = local_once(&hash, once_expires_at(&request.resolved_at)?)?;
        }
    } else if persist.is_none() && scope == "artifact" && !request.temporary_mcp {
        persistence = "once";
        let expires_at = once_expires_at(&request.resolved_at)?;
        once_expiry = Some(expires_at.clone());
        if allow && request.requires_local_once {
            local_once_row = local_once(&scoped_hash, expires_at)?;
        }
    } else if persist == Some(false)
        && scope == "artifact"
        && exact_context_allow
        && !request.temporary_mcp
        && !request.local_tool
    {
        // "Do not remember" still authorizes the exact approved retry once.
        persistence = "exact_once";
        local_once_row = local_once(&scoped_hash, once_expires_at(&request.resolved_at)?)?;
    }

    let runtime_exact_scoped = scope == "artifact"
        && scoped_hash
            .as_deref()
            .is_some_and(|hash| hash.starts_with(RUNTIME_EXACT_PREFIX));
    let resolve_matching = request.resolve_scope_matches
        && !(allow && scope != "artifact")
        && !runtime_exact_scoped
        && !exact_context_allow;
    let matching = if resolve_matching {
        let harness = if scope == "global" {
            Value::Null
        } else {
            json!(approval.harness.clone().ok_or_else(|| INVALID.to_owned())?)
        };
        json!({
            "harness": harness,
            "scope": scope,
            "artifact_id": scoped_id,
            "artifact_hash": request_artifact_hash,
            "workspace": workspace,
            "publisher": (scope == "publisher").then(|| approval.publisher.clone()).flatten(),
        })
    } else {
        Value::Null
    };
    Ok(json!({
        "decision": decision,
        "persistence": persistence,
        "once_expires_at": once_expiry,
        "local_once": local_once_row,
        "matching": matching,
        "exact_context_allow": exact_context_allow,
    }))
}

#[cfg(test)]
#[path = "approval_resolution_plan_vectors_tests.rs"]
mod vectors;
