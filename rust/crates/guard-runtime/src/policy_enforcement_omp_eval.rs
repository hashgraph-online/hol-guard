//! Recheck a bounded read-only eval input after its output has been scanned.
use guard_contracts::{NativeHookRequestV1, PreToolActionTypeV1};
use serde_json::Value;

pub(super) fn bounded_read_output(request: &NativeHookRequestV1) -> bool {
    if request.harness != "omp" {
        return false;
    }
    let Some(root) = request.payload.as_object() else {
        return false;
    };
    if root.get("tool_name").and_then(Value::as_str) != Some("eval") {
        return false;
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
    proof.minimum_action == "allow"
        && !proof.action.sensitive_target
        && proof.action.action_type == PreToolActionTypeV1::FileRead
        && proof.reason_code == "native_omp_eval_bounded_tools"
}
