use guard_command::CommandModelRequestV1;
use guard_contracts::{
    ApprovalChallengeRequestV3, ApprovalChallengeRequestV4, ApprovalConsumeRequestV3,
    ApprovalConsumeRequestV4, ApprovalValidateRequestV3, ApprovalValidateRequestV4,
    GuardHookEnvelopeV2, NativeHookRequestV1, RuntimeCapabilitiesV1, GUARD_HOOK_ENVELOPE_V2_SCHEMA,
    MAX_NATIVE_RESPONSE_BYTES, NATIVE_APPROVAL_ERROR_CODES, NATIVE_APPROVAL_MAX_BYTES,
    NATIVE_PROTOCOL_VERSION, NATIVE_RESIDENT_LIFECYCLE_ERROR_CODES,
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
    ApprovalChallenge(ApprovalChallengeRequestV3),
    ApprovalValidate(ApprovalValidateRequestV3),
    ApprovalConsume(ApprovalConsumeRequestV3),
    ApprovalChallengeV4(ApprovalChallengeRequestV4),
    ApprovalValidateV4(ApprovalValidateRequestV4),
    ApprovalConsumeV4(ApprovalConsumeRequestV4),
    Health(Value),
    Shutdown(Value),
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(crate) enum ResidentRequestV1 {
    Operation(Box<ResidentOperationV1>),
    Edge(GuardHookEnvelopeV2),
    Hook(NativeHookRequestV1),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LifecycleDisposition {
    Continue,
    Shutdown,
}

#[derive(Debug)]
pub(crate) struct ResidentEvaluation {
    pub(crate) response: Vec<u8>,
    pub(crate) disposition: LifecycleDisposition,
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
        guard_contracts::NATIVE_COMMAND_PROGRAM_CAPABILITY.into(),
        guard_contracts::NATIVE_COMMAND_CONTROL_FENCE_CAPABILITY.into(),
        "policy-snapshot-v3".into(),
        "policy-snapshot-push-v1".into(),
        "policy-snapshot-resident-generation-v1".into(),
        "native-approval-artifact-v3".into(),
        "native-approval-challenge-v3".into(),
        "native-approval-validation-v3".into(),
        "native-approval-consume-v3".into(),
        "native-approval-webauthn-v4".into(),
        "native-approval-challenge-v4".into(),
        "native-approval-validation-v4".into(),
        "native-approval-consume-v4".into(),
        "native-approval-replay-memory-v1".into(),
        "native-policy-in-memory-v1".into(),
        "hook-envelope-v2".into(),
        "native-resident-client-v1".into(),
        "native-resident-lifecycle-v1".into(),
    ];
    if cfg!(windows) {
        features.push("authenticated-loopback-resident-v1".into());
        features.push("post-tool-source-read-windows-handles-v1".into());
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

#[cfg(test)]
pub(crate) fn evaluate_resident_bytes(
    bytes: &[u8],
    policy_store: Option<&PolicySnapshotStore>,
) -> Result<ResidentEvaluation, String> {
    evaluate_resident_bytes_started(bytes, policy_store, std::time::Instant::now())
}

pub(crate) fn evaluate_resident_bytes_started(
    bytes: &[u8],
    policy_store: Option<&PolicySnapshotStore>,
    started_at: std::time::Instant,
) -> Result<ResidentEvaluation, String> {
    let value = strict_json_value(bytes)?;
    if bytes.len() > NATIVE_APPROVAL_MAX_BYTES
        && matches!(
            value.get("operation").and_then(Value::as_str),
            Some(
                "approval_challenge"
                    | "approval_validate"
                    | "approval_consume"
                    | "approval_challenge_v4"
                    | "approval_validate_v4"
                    | "approval_consume_v4",
            )
        )
    {
        return Err("native_approval_request_bounds_exceeded".to_owned());
    }
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
    let mut disposition = LifecycleDisposition::Continue;
    let response = match request {
        ResidentRequestV1::Edge(request) => {
            let policy_store =
                policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
            crate::edge::evaluate_envelope_with_store_started(request, policy_store, started_at)
        }
        ResidentRequestV1::Operation(request) => match *request {
            ResidentOperationV1::CommandModel(request) => {
                crate::oneshot::evaluate_command_model_request(&request)
            }
            ResidentOperationV1::PreToolUse(request) => {
                crate::oneshot::evaluate_pre_tool_request(&request)
            }
            ResidentOperationV1::PolicySnapshotPush(request) => {
                let policy_store =
                    policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
                policy_store.push(&request)
            }
            ResidentOperationV1::ApprovalChallenge(request) => {
                let policy_store =
                    policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
                crate::approval::create_challenge(request, policy_store)
            }
            ResidentOperationV1::ApprovalValidate(request) => {
                let policy_store =
                    policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
                crate::approval::validate_approval(request, policy_store)
            }
            ResidentOperationV1::ApprovalConsume(request) => {
                let policy_store =
                    policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
                crate::approval::consume_approval(request, policy_store)
            }
            ResidentOperationV1::ApprovalChallengeV4(request) => {
                let policy_store =
                    policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
                crate::approval::approval_v4::create_challenge(request, policy_store)
            }
            ResidentOperationV1::ApprovalValidateV4(request) => {
                let policy_store =
                    policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
                crate::approval::approval_v4::validate_approval(request, policy_store)
            }
            ResidentOperationV1::ApprovalConsumeV4(request) => {
                let policy_store =
                    policy_store.ok_or_else(|| "native_policy_snapshot_unavailable".to_owned())?;
                crate::approval::approval_v4::consume_approval(request, policy_store)
            }
            ResidentOperationV1::Health(_request) => encode_response(&serde_json::json!({
                "status": "ready",
                "protocol_version": crate::RESIDENT_PROTOCOL_VERSION,
            })),
            ResidentOperationV1::Shutdown(_request) => {
                disposition = LifecycleDisposition::Shutdown;
                encode_response(&serde_json::json!({"status": "stopping"}))
            }
        },
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
    }?;
    Ok(ResidentEvaluation {
        response,
        disposition,
    })
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
    if NATIVE_RESIDENT_LIFECYCLE_ERROR_CODES.contains(&code)
        || NATIVE_APPROVAL_ERROR_CODES.contains(&code)
        || guard_contracts::NATIVE_COMMAND_CONTROL_ERROR_CODES.contains(&code)
    {
        return serde_json::to_vec(&serde_json::json!({
            "error": code,
            "retryable": retryable,
        }))
        .unwrap_or_else(|_| error_response("native_response_encode_failed", false));
    }
    error_response("native_request_invalid_json", retryable)
}

#[cfg(test)]
mod tests {
    use super::{evaluate_resident_bytes, safe_error_response};
    use serde_json::Value;

    #[test]
    fn lifecycle_disposition_follows_strictly_validated_operation() {
        for (operation, disposition, status) in [
            ("health", super::LifecycleDisposition::Continue, "ready"),
            (
                "shutdown",
                super::LifecycleDisposition::Shutdown,
                "stopping",
            ),
        ] {
            let request = format!(r#"{{"operation":"{operation}","request":{{}}}}"#);
            let evaluated = evaluate_resident_bytes(request.as_bytes(), None).unwrap();
            assert_eq!(evaluated.disposition, disposition);
            let response: Value = serde_json::from_slice(&evaluated.response).unwrap();
            assert_eq!(response["status"], status);
        }
        for malformed in [
            br#"{"operation":"health","operation":"shutdown","request":{}}"#.as_slice(),
            br#"{"operation":"shutdown"}"#.as_slice(),
            br#"{"operation":"shutdown","request":{}} {}"#.as_slice(),
        ] {
            assert!(evaluate_resident_bytes(malformed, None).is_err());
        }
    }

    #[test]
    fn command_control_error_transport_preserves_only_registered_fixed_codes() {
        for code in guard_contracts::NATIVE_COMMAND_CONTROL_ERROR_CODES {
            for retryable in [false, true] {
                let response: Value =
                    serde_json::from_slice(&safe_error_response(code, retryable)).unwrap();
                assert_eq!(response["error"], *code);
                assert_eq!(response["retryable"], retryable);
                assert_eq!(response.as_object().unwrap().len(), 2);
            }
        }
        for untrusted in [
            "native_command_control_future_unregistered_code",
            "native_command_control_authority_missing:/private/guard-home",
            "native_command_control_authority_mac_invalid secret=fixture",
        ] {
            let response: Value =
                serde_json::from_slice(&safe_error_response(untrusted, false)).unwrap();
            assert_eq!(response["error"], "native_request_invalid_json");
        }
    }

    #[test]
    fn approval_error_transport_is_finite() {
        let known: Value =
            serde_json::from_slice(&safe_error_response("native_approval_replay", false))
                .expect("known approval error is JSON");
        assert_eq!(known["error"], "native_approval_replay");

        let unknown: Value = serde_json::from_slice(&safe_error_response(
            "native_approval_future_unregistered_code",
            false,
        ))
        .expect("redacted approval error is JSON");
        assert_eq!(unknown["error"], "native_request_invalid_json");

        let lifecycle: Value = serde_json::from_slice(&safe_error_response(
            "native_resident_start_in_progress",
            true,
        ))
        .expect("known lifecycle error is JSON");
        assert_eq!(lifecycle["error"], "native_resident_start_in_progress");

        let unknown_lifecycle: Value = serde_json::from_slice(&safe_error_response(
            "native_resident_future_unregistered_code",
            false,
        ))
        .expect("redacted lifecycle error is JSON");
        assert_eq!(unknown_lifecycle["error"], "native_request_invalid_json");

        let unknown_policy: Value = serde_json::from_slice(&safe_error_response(
            "native_policy_snapshot_future_unregistered_code",
            false,
        ))
        .expect("redacted policy error is JSON");
        assert_eq!(unknown_policy["error"], "native_request_invalid_json");
    }

    #[test]
    fn approval_requests_have_a_smaller_raw_payload_bound() {
        let padding = "x".repeat(super::NATIVE_APPROVAL_MAX_BYTES);
        let request =
            format!(r#"{{"operation":"approval_challenge","request":{{"padding":"{padding}"}}}}"#);
        assert_eq!(
            evaluate_resident_bytes(request.as_bytes(), None).unwrap_err(),
            "native_approval_request_bounds_exceeded"
        );
    }
}
