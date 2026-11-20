//! Resident-owned explanation for a hook policy admission failure.
//!
//! The hook route still waits for the publisher's acknowledgement in Python,
//! but the decision about which recovery posture to communicate belongs to
//! the Rust control plane. This operation accepts only bounded, privacy-safe
//! failure state and returns the fixed user-facing reason.

use serde::Deserialize;
use serde_json::json;

use crate::resident_protocol::encode_response;

pub(crate) const HOOK_POLICY_ADMISSION_FEATURE: &str = "hook-policy-admission-v1";
const REQUEST_SCHEMA: &str = "guard-hook-policy-admission-request.v1";
const RESULT_SCHEMA: &str = "guard-hook-policy-admission-result.v1";
const RESIDENT_FAIL_FAST_STREAK: u64 = 4;

const POLICY_SOURCE_FENCE_ERROR: &str = "native_business_source_mutation_in_progress";
const PERSISTENT_ERROR: &str = "native_command_program_binding_mismatch";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HookPolicyAdmissionRequestV1 {
    pub(crate) schema: String,
    pub(crate) request_id: String,
    #[serde(default)]
    pub(crate) last_error: Option<String>,
    #[serde(default)]
    pub(crate) resident_failure_streak: Option<u64>,
}

fn resident_class_error(code: &str) -> bool {
    code.starts_with("native_client_")
        || code.starts_with("native_frame_")
        || code.starts_with("native_resident_")
        || code == "native_resident_start_in_progress"
        || code == "native_resident_restart_budget_busy"
}

fn reason(last_error: Option<&str>, resident_failure_streak: u64) -> String {
    const PREFIX: &str = "HOL Guard could not prepare the native policy safely.";
    const RETRY: &str = "This is usually temporary. Retry this action.";
    const REPAIR: &str = "Guard's installed files disagree, so retrying will not clear it. Ask the user to run `hol-guard doctor`.";
    const RESIDENT_DOWN: &str = "Guard's native runtime is not answering. Retry once more; if it still fails, ask the user to run `hol-guard repair` in a terminal.";

    let Some(code) = last_error.filter(|code| !code.is_empty()) else {
        return format!("{PREFIX} {RETRY}");
    };
    if code == POLICY_SOURCE_FENCE_ERROR {
        return "Guard is finishing a policy update; this action was not run. Retry after 8 seconds.".to_owned();
    }
    let advice =
        if resident_class_error(code) && resident_failure_streak >= RESIDENT_FAIL_FAST_STREAK {
            RESIDENT_DOWN
        } else if code == PERSISTENT_ERROR {
            REPAIR
        } else {
            RETRY
        };
    format!("{PREFIX} {code}. {advice}")
}

pub(crate) fn evaluate(request: &HookPolicyAdmissionRequestV1) -> Result<Vec<u8>, String> {
    if request.schema != REQUEST_SCHEMA
        || request.request_id.is_empty()
        || request.request_id.len() > 128
        || request
            .last_error
            .as_ref()
            .is_some_and(|code| code.len() > 128)
        || request
            .last_error
            .as_ref()
            .is_some_and(|code| code.chars().any(|character| character.is_control()))
        || request.resident_failure_streak.unwrap_or(0) > 1_000_000
    {
        return Err("hook_policy_admission_payload_invalid".to_owned());
    }
    encode_response(&json!({
        "schema": RESULT_SCHEMA,
        "result": {
            "request_id": request.request_id,
            "reason": reason(request.last_error.as_deref(), request.resident_failure_streak.unwrap_or(0)),
        },
    }))
}

#[cfg(test)]
#[path = "hook_policy_admission_op_tests.rs"]
mod tests;
