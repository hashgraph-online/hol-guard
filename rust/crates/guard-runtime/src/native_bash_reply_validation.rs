//! Wire validation belongs to the native Bash owner, not its Python adapters.
//! Validation observes replies; it neither grants consent nor starts a launch.

use guard_contracts::{
    native_bash_operation_id_is_valid, NativeBashAuthorizationKindV1 as Authorization,
    NativeBashExecuteResultV1, NativeBashOperationStateV1 as State, NativeBashReviewLineageV1,
    NATIVE_BASH_ARTIFACT_ID,
};
use serde_json::Value;

fn token(value: &str) -> bool {
    value.starts_with("guard-approval-context:v1:")
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn keys(value: &Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|map| {
        map.len() == expected.len() && expected.iter().all(|key| map.contains_key(*key))
    })
}

pub(crate) fn lineage(value: &Value) -> bool {
    let Ok(value) = serde_json::from_value::<NativeBashReviewLineageV1>(value.clone()) else {
        return false;
    };
    value.schema == "guard-native-bash-review-lineage.v1"
        && digest(&value.lineage_id)
        && native_bash_operation_id_is_valid(&value.operation_id)
        && token(&value.artifact_hash)
        && value.expires_at_ms.checked_sub(value.created_at_ms) == Some(86_400_000)
}

pub(crate) fn prepared(value: &Value) -> bool {
    let expected = [
        "subject",
        "artifact_id",
        "artifact_hash",
        "assessment",
        "consent_required",
        "review",
    ];
    let Some(map) = value.as_object() else {
        return false;
    };
    if !expected.iter().all(|key| map.contains_key(*key))
        || map
            .keys()
            .any(|key| !expected.contains(&key.as_str()) && key != "dependency_artifact")
        || value["artifact_id"] != NATIVE_BASH_ARTIFACT_ID
        || !value["artifact_hash"].as_str().is_some_and(token)
        || !value["assessment"].is_array()
        || !value["consent_required"].is_boolean()
        || !keys(&value["review"], &["decision", "receipt"])
        || !value["review"]["decision"].is_object()
        || !value["review"]["receipt"].is_object()
        || value["subject"]["schema"] != "guard.bash-subject.v1"
        || !matches!(
            value["subject"]["execution_assurance"].as_str(),
            Some(
                "macos-readonly-root-framed-outputs-v1"
                    | "macos-readonly-root-http-read-v1"
                    | "macos-hardened-broker-v1"
            )
        )
    {
        return false;
    }
    let Some(artifact) = map.get("dependency_artifact") else {
        return true;
    };
    let metadata = &artifact["metadata"];
    let host = match artifact["harness"].as_str() {
        Some("omp") => "omp-input-rewrite-v1",
        Some("pi") => "pi-input-mutation-v1",
        _ => return false,
    };
    artifact["artifact_type"] == "package_request"
        && metadata["assessment_only"] == true
        && value["subject"]["context"]["host"] == host
        && value["subject"]["package_bindings"]
            .as_array()
            .is_some_and(|bindings| !bindings.is_empty())
        && metadata["captured_subject_sha256"]
            .as_str()
            .is_some_and(|hash| {
                digest(hash)
                    && artifact["artifact_id"].as_str()
                        == Some(
                            format!(
                                "{}:project:package-request:{hash}",
                                artifact["harness"].as_str().unwrap_or_default()
                            )
                            .as_str(),
                        )
            })
}

pub(crate) fn executed(value: &Value, request: &Value) -> bool {
    if !keys(
        value,
        &[
            "schema",
            "request_id",
            "request_sha256",
            "status",
            "code",
            "payload",
            "grant_claimed",
            "dispatch_acknowledged",
            "replayed",
            "operation",
            "review_lineage",
        ],
    ) {
        return false;
    }
    let Ok(result) = serde_json::from_value::<NativeBashExecuteResultV1>(value.clone()) else {
        return false;
    };
    // The owner checks SDK allocations against its authenticated journal in
    // bash_route::reply_is_backed before encoding. This stateless wire check
    // binds the transport header and validates the allocated ID's shape.
    let operation_matches = |id: &str| {
        if request
            .get("tool_call_id")
            .is_some_and(|value| !value.is_null())
        {
            id.strip_prefix("bash-invocation:").is_some_and(digest)
        } else {
            request["operation_id"].as_str() == Some(id)
        }
    };
    if let Some(review) = &result.review_lineage {
        if !lineage(&value["review_lineage"])
            || !operation_matches(&review.operation_id)
            || result.status != "error"
            || result.code != "native_bash_consent_required"
            || result.grant_claimed
            || result.dispatch_acknowledged
            || result.replayed
            || result.operation.is_some()
            || result.payload.is_some()
        {
            return false;
        }
    } else if result.code == "native_bash_consent_required" {
        return false;
    }
    if let Some(operation) = &result.operation {
        let authorization = match operation.authorization {
            Authorization::SavedGrant => "saved_grant",
            Authorization::CurrentPolicy => "current_policy",
        };
        if !operation_matches(&operation.operation_id)
            || !request["authorization"].is_object()
            || if result.replayed {
                result.grant_claimed != (operation.authorization == Authorization::SavedGrant)
            } else {
                request["authorization"]["kind"].as_str() != Some(authorization)
            }
            || operation.dispatch_acknowledged != result.dispatch_acknowledged
            || !token(&operation.artifact_hash)
            || (operation.state == State::Completed) != operation.completion.is_some()
            || operation.completion.as_ref().is_some_and(|completion| {
                !digest(&completion.stdout_sha256) || !digest(&completion.stderr_sha256)
            })
        {
            return false;
        }
    }
    match result.status.as_str() {
        "ok" => {
            result.dispatch_acknowledged
                && !result.replayed
                && result.payload.is_some()
                && result
                    .operation
                    .is_some_and(|operation| operation.state == State::Completed)
        }
        "recorded" => {
            result.replayed
                && result.operation.is_some()
                && result.payload.is_none()
                && matches!(
                    result.code.as_str(),
                    "native_bash_already_completed_output_not_retained"
                        | "native_bash_operation_in_progress_or_uncertain"
                )
        }
        _ => !result.replayed,
    }
}

/// Validate at the existing owning native client boundary, without another
/// resident round trip or copying large completion output through adapters.
#[cfg(any(test, target_os = "macos"))]
pub(crate) fn bound_execution(value: &Value, request: &Value) -> bool {
    let expected = crate::package_authority_op::request_digest_with_limit(
        request,
        guard_contracts::NATIVE_BASH_LAUNCH_MAX_REQUEST_BYTES,
    );
    let code = value["code"].as_str().unwrap_or_default();
    value["schema"] == guard_contracts::NATIVE_BASH_EXECUTE_RESULT_SCHEMA
        && value["request_id"].is_string()
        && value["request_id"] == request["request_id"]
        && expected.is_ok_and(|digest| value["request_sha256"].as_str() == Some(digest.as_str()))
        && matches!(value["status"].as_str(), Some("ok" | "error" | "recorded"))
        && (1..=128).contains(&code.len())
        && code.as_bytes()[0].is_ascii_lowercase()
        && code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        && (value["status"] == "ok") == (code == "ok")
        && executed(value, request)
}

pub(crate) fn validate(kind: &str, material: &Value, request: &Value) -> bool {
    match kind {
        "prepared" => prepared(material),
        "executed" => executed(material, request),
        "lineage" => lineage(material),
        _ => false,
    }
}

#[cfg(test)]
#[path = "native_bash_reply_validation_tests.rs"]
mod tests;
