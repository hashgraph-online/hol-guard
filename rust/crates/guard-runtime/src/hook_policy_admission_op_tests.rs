use super::{evaluate, HookPolicyAdmissionRequestV1};
use serde_json::Value;

fn request(last_error: Option<&str>, streak: u64) -> HookPolicyAdmissionRequestV1 {
    HookPolicyAdmissionRequestV1 {
        schema: "guard-hook-policy-admission-request.v1".to_owned(),
        request_id: "request-1".to_owned(),
        last_error: last_error.map(str::to_owned),
        resident_failure_streak: Some(streak),
    }
}

fn reason(last_error: Option<&str>, streak: u64) -> String {
    let value: Value = serde_json::from_slice(&evaluate(&request(last_error, streak)).unwrap())
        .expect("valid admission response");
    value["result"]["reason"]
        .as_str()
        .expect("reason")
        .to_owned()
}

#[test]
fn no_error_uses_retry_advice() {
    assert_eq!(
        reason(None, 0),
        "HOL Guard could not prepare the native policy safely. This is usually temporary. Retry this action."
    );
}

#[test]
fn persistent_install_error_requires_repair() {
    assert!(reason(Some("native_command_program_binding_mismatch"), 1).contains("hol-guard doctor"));
}

#[test]
fn repeated_resident_failures_require_repair() {
    let value = reason(Some("native_client_timed_out"), 4);
    assert!(value.contains("Retry once more"));
    assert!(value.contains("hol-guard repair"));
}

#[test]
fn policy_source_fence_has_fixed_retry_window() {
    assert_eq!(
        reason(Some("native_business_source_mutation_in_progress"), 4),
        "Guard is finishing a policy update; this action was not run. Retry after 8 seconds."
    );
}

#[test]
fn malformed_state_is_rejected() {
    let mut request = request(Some("bad\ncode"), 0);
    assert_eq!(
        evaluate(&request).unwrap_err(),
        "hook_policy_admission_payload_invalid"
    );
    request.last_error = Some("ok".repeat(129));
    assert_eq!(
        evaluate(&request).unwrap_err(),
        "hook_policy_admission_payload_invalid"
    );
}
