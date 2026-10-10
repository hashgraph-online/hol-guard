//! Recheck bounded OMP eval reads and result reports after output scanning.
use guard_contracts::{NativeHookRequestV1, PreToolActionTypeV1};
use serde_json::Value;

pub(super) fn bounded_output_action(request: &NativeHookRequestV1) -> Option<PreToolActionTypeV1> {
    if request.harness != "omp" {
        return None;
    }
    let root = request.payload.as_object()?;
    if !matches!(
        root.get("tool_name").and_then(Value::as_str),
        Some("eval" | "yield")
    ) {
        return None;
    }
    let input = Value::Object(
        root.iter()
            .filter(|(key, _)| {
                !matches!(
                    key.as_str(),
                    "tool_response" | "toolResponse" | "toolResultPreview"
                )
            })
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    );
    let proof = guard_command::pretool::evaluate_pre_tool_envelope_with_context(
        &request.harness,
        "PreToolUse",
        &input,
        None,
        Some(std::time::Instant::now() + std::time::Duration::from_millis(100)),
        Some(&request.home_dir),
        request.cwd.as_deref(),
    );
    let proof =
        crate::omp_yield_input_scan::scan(&input, request.deadline_budget_ms, proof).ok()?;
    if proof.minimum_action != "allow" || proof.action.sensitive_target {
        return None;
    }
    match (proof.reason_code.as_str(), proof.action.action_type) {
        ("native_omp_eval_bounded_tools", PreToolActionTypeV1::FileRead) => {
            Some(PreToolActionTypeV1::FileRead)
        }
        ("native_omp_yield_metadata", PreToolActionTypeV1::Harness) => {
            Some(PreToolActionTypeV1::Harness)
        }
        _ => None,
    }
}
