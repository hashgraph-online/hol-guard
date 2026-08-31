use guard_command::CommandModelRequestV1;
use guard_contracts::{
    GuardHookEnvelopeV2, NativeHookRequestV1, RuntimeCapabilitiesV1, GUARD_HOOK_ENVELOPE_V2_SCHEMA,
    MAX_NATIVE_RESPONSE_BYTES, NATIVE_PROTOCOL_VERSION,
};
use guard_hook_core::review_post_tool;
use serde::Deserialize;
use serde_json::Value;

use crate::policy_store::PolicySnapshotStore;

#[derive(Debug, Deserialize)]
#[serde(tag = "operation", content = "request", rename_all = "snake_case")]
pub(crate) enum ResidentOperationV1 {
    CommandModel(CommandModelRequestV1),
    PreToolUse(CommandModelRequestV1),
    PolicySnapshotPush(Value),
    Health(Value),
    Shutdown(Value),
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(crate) enum ResidentRequestV1 {
    Operation(ResidentOperationV1),
    Edge(GuardHookEnvelopeV2),
    Hook(NativeHookRequestV1),
}

pub(crate) fn capabilities() -> RuntimeCapabilitiesV1 {
    let mut features = vec![
        "post-tool-inline-v1".into(),
        "post-tool-source-read-v1".into(),
        "oneshot-v1".into(),
        "framed-serve-v1".into(),
        "resident-protocol-v2".into(),
        "bounded-admission-v2".into(),
        "overload-signal-v1".into(),
        "panic-containment-v1".into(),
        "rule-contract-v2".into(),
        "pre-tool-command-model-shadow-v1".into(),
        "resident-command-model-shadow-v1".into(),
        "pre-tool-command-authority-v1".into(),
        "pre-tool-generic-authority-v1".into(),
        "policy-snapshot-v3".into(),
        "policy-snapshot-push-v1".into(),
        "native-policy-in-memory-v1".into(),
        "hook-envelope-v2".into(),
        "native-resident-client-v1".into(),
        "native-resident-lifecycle-v1".into(),
    ];
    if cfg!(windows) {
        features.push("authenticated-loopback-resident-v1".into());
    }
    if cfg!(unix) {
        features.push("authenticated-unix-resident-v1".into());
    }
    RuntimeCapabilitiesV1 {
        protocol_version: NATIVE_PROTOCOL_VERSION,
        runtime_version: crate::PACKAGE_VERSION.to_owned(),
        rule_digest: guard_rule_contract::rule_digest(),
        build_sha: crate::BUILD_SHA.to_owned(),
        target: format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
        features,
    }
}

pub(crate) fn evaluate_resident_bytes(
    bytes: &[u8],
    policy_store: Option<&PolicySnapshotStore>,
) -> Result<Vec<u8>, String> {
    let value = strict_json_value(bytes)?;
    if value.get("operation").and_then(Value::as_str) == Some("policy_snapshot_push") {
        let object = value
            .as_object()
            .ok_or_else(|| "native_policy_snapshot_push_invalid".to_owned())?;
        if object
            .keys()
            .any(|key| !matches!(key.as_str(), "operation" | "request" | "deadline_budget_ms"))
        {
            return Err("native_policy_snapshot_push_invalid".to_owned());
        }
    }
    if value.get("operation").is_none()
        && value.get("schema").and_then(Value::as_str) != Some(GUARD_HOOK_ENVELOPE_V2_SCHEMA)
    {
        crate::oneshot::validate_request_policy_snapshot(&value)?;
    }
    let request: ResidentRequestV1 = serde_json::from_value(value)
        .map_err(|_| "native_resident_request_invalid_json".to_owned())?;
    match request {
        ResidentRequestV1::Edge(request) => {
            let policy_store =
                policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
            crate::edge::evaluate_envelope_with_store(request, policy_store)
        }
        ResidentRequestV1::Operation(ResidentOperationV1::CommandModel(request)) => {
            crate::oneshot::evaluate_command_model_request(&request)
        }
        ResidentRequestV1::Operation(ResidentOperationV1::PreToolUse(request)) => {
            crate::oneshot::evaluate_pre_tool_request(&request)
        }
        ResidentRequestV1::Operation(ResidentOperationV1::PolicySnapshotPush(request)) => {
            let policy_store =
                policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
            policy_store.push(&request)
        }
        ResidentRequestV1::Operation(ResidentOperationV1::Health(_request)) => {
            encode_response(&serde_json::json!({
                "status": "ready",
                "protocol_version": crate::RESIDENT_PROTOCOL_VERSION,
            }))
        }
        ResidentRequestV1::Operation(ResidentOperationV1::Shutdown(_request)) => {
            crate::managed_resident::request_shutdown();
            encode_response(&serde_json::json!({"status": "stopping"}))
        }
        ResidentRequestV1::Hook(request) => {
            // Managed residents always carry a v3 policy store. The legacy
            // request has no generation-bound snapshot and must never reach a
            // semantic evaluator in that path.
            if policy_store.is_some() {
                Err("native_policy_snapshot_required".to_owned())
            } else {
                encode_response(&review_post_tool(&request))
            }
        }
    }
}

pub(crate) fn strict_json_value(bytes: &[u8]) -> Result<Value, String> {
    crate::strict_json::parse(bytes)
}

pub(crate) fn encode_response<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let encoded =
        serde_json::to_vec(value).map_err(|_| "native_response_encode_failed".to_owned())?;
    if encoded.len() > MAX_NATIVE_RESPONSE_BYTES {
        return Err("native_response_too_large".to_owned());
    }
    Ok(encoded)
}

pub(crate) fn error_response(code: &'static str, retryable: bool) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"error": code, "retryable": retryable})).unwrap_or_else(
        |_| b"{\"error\":\"native_response_encode_failed\",\"retryable\":false}".to_vec(),
    )
}

pub(crate) fn safe_error_response(code: &str, retryable: bool) -> Vec<u8> {
    if code.starts_with("native_policy_snapshot_") || code.starts_with("snapshot_") {
        return serde_json::to_vec(&serde_json::json!({
            "error": code,
            "retryable": retryable,
        }))
        .unwrap_or_else(|_| error_response("native_response_encode_failed", false));
    }
    error_response("native_request_invalid_json", retryable)
}
