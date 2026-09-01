use super::approval_replay_memory::ApprovalReplayBinding;
use super::{ACTION_IDENTITY_MAX_BYTES, APPROVAL_RUNTIME_PACKAGE, APPROVAL_RUNTIME_VERSION};
use guard_contracts::{
    GuardHookEdgeResultV2, NativeActionIdentityV3, NativeApprovalFloorClassV3, PreToolActionTypeV1,
    PreToolOperationV1, NATIVE_ACTION_IDENTITY_V3_SCHEMA, NATIVE_APPROVAL_CHALLENGE_V3_SCHEMA,
    NATIVE_APPROVAL_DEVICE_BINDING_DOMAIN, NATIVE_APPROVAL_INSTALLATION_BINDING_DOMAIN,
    NATIVE_APPROVAL_MAX_STRING_BYTES, NATIVE_PROTOCOL_VERSION,
};
use guard_policy_snapshot::{canonical_json_bytes, digest_bytes};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub(super) struct ApprovalContext {
    pub(super) request_id: String,
    pub(super) request_digest: String,
    pub(super) action_digest: String,
    pub(super) action_type: PreToolActionTypeV1,
    pub(super) operation: PreToolOperationV1,
    pub(super) intrinsic_action: String,
    pub(super) minimum_action: String,
    pub(super) policy_generation: u64,
    pub(super) policy_digest: String,
    pub(super) rule_digest: String,
    pub(super) runtime_identity: String,
    pub(super) harness: String,
    pub(super) workspace_binding: Option<String>,
    pub(super) device_binding: Option<String>,
    pub(super) installation_binding: Option<String>,
    pub(super) publisher_binding: Option<String>,
    pub(super) artifact_binding: Option<String>,
    pub(super) scope_contract_version: String,
    pub(super) scope_contract_digest: String,
    pub(super) scope_binding: Option<String>,
    pub(super) action_identity: NativeActionIdentityV3,
}

pub(super) fn now_ms() -> Result<u64, String> {
    let value = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "native_resident_clock_invalid".to_owned())?
        .as_millis();
    u64::try_from(value).map_err(|_| "native_resident_clock_invalid".to_owned())
}

pub(super) fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn bounded_string(
    value: &str,
    allow_empty: bool,
    maximum: usize,
    code: &str,
) -> Result<(), String> {
    if (!allow_empty && value.trim().is_empty())
        || value.len() > maximum
        || value.chars().count() > maximum
    {
        return Err(code.to_owned());
    }
    Ok(())
}

pub(super) fn valid_binding(value: Option<&String>) -> Result<(), String> {
    if let Some(value) = value {
        if !is_lower_hex(value, 64) {
            return Err("native_approval_binding_invalid".to_owned());
        }
    }
    Ok(())
}

fn action_rank(value: &str) -> Option<u8> {
    Some(match value {
        "allow" => 0,
        "warn" => 1,
        "review" => 2,
        "require-reapproval" => 3,
        "sandbox-required" => 4,
        "block" => 5,
        _ => return None,
    })
}

pub(super) fn is_approvable_floor(value: &str) -> bool {
    matches!(value, "review" | "require-reapproval")
}

pub(super) fn encode_digest(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

fn canonical_digest<T: Serialize>(value: &T, maximum: usize, code: &str) -> Result<String, String> {
    let value = serde_json::to_value(value).map_err(|_| code.to_owned())?;
    let bytes = canonical_json_bytes(&value).map_err(|_| code.to_owned())?;
    if bytes.len() > maximum {
        return Err(code.to_owned());
    }
    Ok(digest_bytes(&bytes))
}

fn binding_digest(label: &str, values: &[&str]) -> Result<String, String> {
    let mut normalized = values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    normalized.sort_unstable();
    normalized.dedup();
    if normalized.is_empty() {
        return Err("native_approval_binding_invalid".to_owned());
    }
    canonical_digest(
        &serde_json::json!({"label": label, "values": normalized}),
        ACTION_IDENTITY_MAX_BYTES,
        "native_approval_binding_invalid",
    )
}

fn collect_binding_values<'a>(
    value: &'a Value,
    keys: &[&str],
    output: &mut Vec<&'a str>,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), String> {
    if depth > 32 {
        return Err("native_approval_request_bounds_exceeded".to_owned());
    }
    *nodes = nodes.saturating_add(1);
    if *nodes > 4_096 {
        return Err("native_approval_request_bounds_exceeded".to_owned());
    }
    match value {
        Value::Object(record) => {
            for (key, child) in record {
                if keys.iter().any(|candidate| *candidate == key)
                    && !child.is_object()
                    && !child.is_array()
                {
                    let text = child
                        .as_str()
                        .ok_or_else(|| "native_approval_binding_invalid".to_owned())?;
                    bounded_string(
                        text,
                        false,
                        NATIVE_APPROVAL_MAX_STRING_BYTES,
                        "native_approval_binding_invalid",
                    )?;
                    output.push(text);
                }
                collect_binding_values(child, keys, output, depth.saturating_add(1), nodes)?;
            }
        }
        Value::Array(items) => {
            for child in items {
                collect_binding_values(child, keys, output, depth.saturating_add(1), nodes)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

fn optional_binding(payload: &Value, keys: &[&str]) -> Result<Option<String>, String> {
    let mut values = Vec::new();
    let mut nodes = 0;
    collect_binding_values(payload, keys, &mut values, 0, &mut nodes)?;
    values.sort_unstable();
    values.dedup();
    if values.len() > 1 {
        return Err("native_approval_binding_ambiguous".to_owned());
    }
    values
        .first()
        .map(|value| binding_digest(keys[0], &[value]))
        .transpose()
}

fn build_action_identity(
    action: &guard_contracts::PreToolActionV1,
    intrinsic_action: &str,
    minimum_action: &str,
    policy_action: &str,
) -> NativeActionIdentityV3 {
    let non_overridable = matches!(
        action.action_type,
        PreToolActionTypeV1::Config | PreToolActionTypeV1::Unknown
    ) || matches!(action.operation, PreToolOperationV1::Unknown)
        || !action.bounded
        || action.event != "PreToolUse"
        || action_rank(intrinsic_action).is_none_or(|rank| rank >= 4)
        || action_rank(minimum_action).is_none_or(|rank| rank >= 4)
        || !is_approvable_floor(minimum_action);
    NativeActionIdentityV3 {
        schema: NATIVE_ACTION_IDENTITY_V3_SCHEMA.to_owned(),
        version: 3,
        harness: action.harness.clone(),
        event: action.event.clone(),
        action_type: action.action_type,
        operation: action.operation,
        bounded: action.bounded,
        sensitive_target: action.sensitive_target,
        intrinsic_action: intrinsic_action.to_owned(),
        minimum_action: minimum_action.to_owned(),
        policy_action: policy_action.to_owned(),
        floor_class: if non_overridable {
            NativeApprovalFloorClassV3::NonOverridable
        } else {
            NativeApprovalFloorClassV3::Approvable
        },
        approval_eligible: !non_overridable && is_approvable_floor(minimum_action),
    }
}

pub(super) fn derive_context_with_snapshot(
    envelope: &guard_contracts::GuardHookEnvelopeV2,
    store: &crate::policy_store::PolicySnapshotStore,
    snapshot: &guard_policy_snapshot::PolicySnapshotV3,
) -> Result<ApprovalContext, String> {
    let edge_bytes = crate::edge::evaluate_envelope_with_snapshot(envelope.clone(), snapshot)
        .map_err(|error| {
            if matches!(
                error.as_str(),
                "native_policy_snapshot_context_mismatch" | "native_policy_snapshot_not_current"
            ) {
                "native_approval_policy_context_mismatch".to_owned()
            } else {
                error
            }
        })?;
    if edge_bytes.len() > guard_contracts::NATIVE_APPROVAL_MAX_BYTES * 2 {
        return Err("native_approval_edge_result_too_large".to_owned());
    }
    let edge_value = crate::strict_json_value(&edge_bytes)
        .map_err(|_| "native_approval_edge_result_invalid".to_owned())?;
    let edge_result: GuardHookEdgeResultV2 = serde_json::from_value(edge_value)
        .map_err(|_| "native_approval_edge_result_invalid".to_owned())?;
    if edge_result.authority != "rust"
        || edge_result.schema != guard_contracts::GUARD_HOOK_EDGE_RESULT_V2_SCHEMA
        || edge_result.event_name != "PreToolUse"
    {
        return Err("native_approval_event_not_approvable".to_owned());
    }
    let request_id = edge_result
        .request_id
        .ok_or_else(|| "native_approval_request_id_missing".to_owned())?;
    let (expected_request_id, request_digest) = crate::edge::request_identity(envelope)?;
    if request_id != expected_request_id {
        return Err("native_approval_request_id_mismatch".to_owned());
    }
    let result: guard_contracts::PreToolResultV1 = serde_json::from_value(edge_result.result)
        .map_err(|_| "native_approval_result_invalid".to_owned())?;
    crate::policy_enforcement::validate_pre_tool_result_matrix(&result)
        .map_err(|_| "native_approval_action_reconstruction_failed".to_owned())?;
    let intrinsic = guard_command::pretool::evaluate_pre_tool_envelope(
        &edge_result.harness,
        &edge_result.event_name,
        &envelope.raw_payload,
    );
    if result.action != intrinsic.action
        || action_rank(&intrinsic.minimum_action).is_none()
        || action_rank(&result.minimum_action).is_none()
        || action_rank(&result.policy_action).is_none()
    {
        return Err("native_approval_action_reconstruction_failed".to_owned());
    }
    let action_identity = build_action_identity(
        &result.action,
        &intrinsic.minimum_action,
        &result.minimum_action,
        &result.policy_action,
    );
    let action_digest = canonical_digest(
        &action_identity,
        ACTION_IDENTITY_MAX_BYTES,
        "native_approval_action_digest_failed",
    )?;
    let workspace_binding = binding_digest(
        "workspace",
        &[
            envelope.source.cwd.as_deref().unwrap_or(""),
            &envelope.source.home_dir,
            &envelope.source.guard_home,
        ],
    )?;
    let scope_binding = binding_digest(
        "scope",
        &[
            snapshot.scope_contract.scope_digest.as_str(),
            workspace_binding.as_str(),
        ],
    )?;
    let device_binding = store.approval_binding(NATIVE_APPROVAL_DEVICE_BINDING_DOMAIN)?;
    let installation_binding =
        store.approval_binding(NATIVE_APPROVAL_INSTALLATION_BINDING_DOMAIN)?;
    let publisher_binding = optional_binding(
        &envelope.raw_payload,
        &[
            "publisher",
            "publisher_id",
            "publisherId",
            "publisher_name",
            "publisherName",
        ],
    )?;
    let artifact_binding = optional_binding(
        &envelope.raw_payload,
        &[
            "artifact",
            "artifact_id",
            "artifactId",
            "package",
            "package_name",
            "packageName",
            "plugin_id",
            "pluginId",
            "extension_id",
            "extensionId",
            "skill_id",
            "skillId",
        ],
    )?;
    Ok(ApprovalContext {
        request_id,
        request_digest,
        action_digest,
        action_type: result.action.action_type,
        operation: result.action.operation,
        intrinsic_action: intrinsic.minimum_action,
        minimum_action: result.minimum_action,
        policy_generation: snapshot.generation,
        policy_digest: snapshot.policy_digest.clone(),
        rule_digest: snapshot.rule_digest.clone(),
        runtime_identity: snapshot.runtime_identity.clone(),
        harness: edge_result.harness,
        workspace_binding: Some(workspace_binding),
        device_binding: Some(device_binding),
        installation_binding: Some(installation_binding),
        publisher_binding,
        artifact_binding,
        scope_contract_version: snapshot.scope_contract.schema.clone(),
        scope_contract_digest: snapshot.scope_contract.scope_digest.clone(),
        scope_binding: Some(scope_binding),
        action_identity,
    })
}

pub(super) fn ensure_context_approvable(context: &ApprovalContext) -> Result<(), String> {
    let Some(intrinsic_rank) = action_rank(&context.intrinsic_action) else {
        return Err("native_approval_intrinsic_action_invalid".to_owned());
    };
    let Some(minimum_rank) = action_rank(&context.minimum_action) else {
        return Err("native_approval_minimum_action_invalid".to_owned());
    };
    if intrinsic_rank >= action_rank("sandbox-required").unwrap_or(4)
        || minimum_rank >= action_rank("sandbox-required").unwrap_or(4)
    {
        return Err("native_approval_floor_not_overridable".to_owned());
    }
    if context.action_identity.floor_class != NativeApprovalFloorClassV3::Approvable
        || !context.action_identity.approval_eligible
        || !is_approvable_floor(&context.minimum_action)
    {
        return Err("native_approval_floor_not_approvable".to_owned());
    }
    if context.action_identity.event != "PreToolUse"
        || context.action_identity.schema != NATIVE_ACTION_IDENTITY_V3_SCHEMA
    {
        return Err("native_approval_action_identity_invalid".to_owned());
    }
    Ok(())
}

pub(super) fn challenge_from_context(
    context: &ApprovalContext,
    nonce: String,
    issued_at_ms: u64,
    expires_at_ms: u64,
    signing_key_id: String,
    resident_epoch: String,
) -> guard_contracts::ApprovalChallengeV3 {
    guard_contracts::ApprovalChallengeV3 {
        schema: NATIVE_APPROVAL_CHALLENGE_V3_SCHEMA.to_owned(),
        version: 3,
        request_id: context.request_id.clone(),
        request_digest: context.request_digest.clone(),
        action_digest: context.action_digest.clone(),
        action_type: context.action_type,
        operation: context.operation,
        intrinsic_action: context.intrinsic_action.clone(),
        minimum_action: context.minimum_action.clone(),
        floor_class: context.action_identity.floor_class,
        approval_eligible: context.action_identity.approval_eligible,
        policy_generation: context.policy_generation,
        policy_digest: context.policy_digest.clone(),
        rule_digest: context.rule_digest.clone(),
        runtime_identity: context.runtime_identity.clone(),
        runtime_protocol_version: NATIVE_PROTOCOL_VERSION,
        runtime_package: APPROVAL_RUNTIME_PACKAGE.to_owned(),
        runtime_version: APPROVAL_RUNTIME_VERSION.to_owned(),
        runtime_binary_identity: context.runtime_identity.clone(),
        harness: context.harness.clone(),
        workspace_binding: context.workspace_binding.clone(),
        device_binding: context.device_binding.clone(),
        installation_binding: context.installation_binding.clone(),
        publisher_binding: context.publisher_binding.clone(),
        artifact_binding: context.artifact_binding.clone(),
        scope_contract_version: context.scope_contract_version.clone(),
        scope_contract_digest: context.scope_contract_digest.clone(),
        scope_binding: context.scope_binding.clone(),
        resident_epoch,
        nonce,
        issued_at_ms,
        expires_at_ms,
        requested_action: context.minimum_action.clone(),
        signing_key_id,
    }
}

pub(super) fn replay_binding(
    context: &ApprovalContext,
    expires_at_ms: u64,
) -> ApprovalReplayBinding {
    ApprovalReplayBinding {
        request_id_digest: encode_digest(context.request_id.as_bytes()),
        request_digest: context.request_digest.clone(),
        action_digest: context.action_digest.clone(),
        policy_generation: context.policy_generation,
        policy_digest: context.policy_digest.clone(),
        rule_digest: context.rule_digest.clone(),
        runtime_identity: context.runtime_identity.clone(),
        runtime_binary_identity: context.runtime_identity.clone(),
        harness: context.harness.clone(),
        workspace_binding: context.workspace_binding.clone(),
        device_binding: context.device_binding.clone(),
        installation_binding: context.installation_binding.clone(),
        publisher_binding: context.publisher_binding.clone(),
        artifact_binding: context.artifact_binding.clone(),
        scope_contract_version: context.scope_contract_version.clone(),
        scope_contract_digest: context.scope_contract_digest.clone(),
        scope_binding: context.scope_binding.clone(),
        expires_at_ms,
    }
}
