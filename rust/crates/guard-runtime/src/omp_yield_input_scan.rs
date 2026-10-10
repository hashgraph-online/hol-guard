//! A yield acknowledgement omits report bytes: scan them before submission.
use guard_contracts::{NativeHookRequestV1, PreToolResultV1, NATIVE_PROTOCOL_VERSION};
use serde_json::{json, Value};

pub(crate) fn scan(
    payload: &Value,
    deadline_budget_ms: Option<u64>,
    mut result: PreToolResultV1,
) -> Result<PreToolResultV1, String> {
    if result.reason_code != "native_omp_yield_metadata" || result.minimum_action != "allow" {
        return Ok(result);
    }
    let text = serde_json::to_string(&payload["tool_input"])
        .map_err(|_| "native_omp_yield_scan_payload_invalid".to_owned())?;
    let scanned = guard_hook_core::review_post_tool(&NativeHookRequestV1 {
        protocol_version: NATIVE_PROTOCOL_VERSION,
        request_id: None,
        harness: "omp".into(),
        event_name: "PostToolUse".into(),
        payload: json!({"tool_response":text}),
        cwd: None,
        home_dir: String::new(),
        guard_home: String::new(),
        source_ref_external_allowed: false,
        observe_mode: false,
        deadline_budget_ms,
    });
    if scanned.decision != "allow" || scanned.model_output_action != "allow_original" {
        result.minimum_action = "block".into();
        result.policy_action = "block".into();
        result.decision = "deny".into();
        result.reason_code = scanned.reason_code;
        result.reason = scanned
            .reason
            .unwrap_or_else(|| "HOL Guard could not safely submit this result report.".into());
        result.explicitly_benign = false;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn submitted_reports_are_scanned_before_the_acknowledgement() {
        for (text, expected) in [
            ("synthetic reference".to_owned(), "allow"),
            (format!("ghp_{}", "A".repeat(36)), "block"),
        ] {
            let payload =
                json!({"tool_name":"yield", "tool_input":{"data":{"report":text,"files":[]}}});
            let native =
                guard_command::pretool::evaluate_pre_tool_envelope("omp", "PreToolUse", &payload);
            assert_eq!(native.minimum_action, "allow");
            let result = scan(&payload, Some(1000), native).unwrap();
            assert_eq!(result.minimum_action, expected);
            crate::policy_enforcement::validate_pre_tool_result_matrix(&result).unwrap();
            if expected == "block" {
                assert_eq!(result.reason_code, "output_secret_match");
            }
        }
    }
}
